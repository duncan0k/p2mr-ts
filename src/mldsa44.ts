/**
 * Wallet side of OP_CHECKMLDSA44, an experimental ML-DSA-44 (FIPS 204) check inside P2MR leaves.
 *
 * The opcode is not part of BIP-360, which defines no post-quantum signature check. It is an
 * experiment of the Ark-0 test signet, where a patched node enforces it at the block level from an
 * activation height H that is fixed in the node's build. This module builds the two leaf templates
 * such a node relays, the outputs that commit to them, their signature messages, signatures and
 * witnesses, and the checks a wallet needs around activation.
 *
 * Encoding (no stack element may exceed 520 bytes, so keys and signatures are split in fixed chunks):
 *
 *   S1:  4d0802 <pk[0]:520> 4d0802 <pk[1]:520> 4d1001 <pk[2]:272> f0
 *   S2:  S1 69 20 <32-byte x-only key> ac        (S1 OP_VERIFY <key> OP_CHECKSIG)
 *   witness:  [<BIP-340 signature> for S2] <sig[0]:520> <sig[1]:520> <sig[2]:520> <sig[3]:520>
 *             <sig[4]:340, or 341 ending in an explicit hash type> <leaf> <control block>
 *
 * The signed message is the BIP-341 tapscript signature message with key_version 1, and the
 * signature is pure ML-DSA-44 over it with the context string "P2MR/MLDSA44/EXP0".
 *
 * Signing uses `@noble/post-quantum`, which states that it has not been independently audited.
 */
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import type { Network } from './address.js';
import { bytesEqual, concatBytes } from './bytes.js';
import { parseControlBlock } from './controlBlock.js';
import { assert, P2mrError } from './errors.js';
import type { P2mrLeafOutput, P2mrOutput } from './output.js';
import { createP2mrOutput, isP2mrScriptPubKey, parseP2mrScriptPubKey } from './output.js';
import type { P2mrScriptPathSighashParams } from './sighash.js';
import { p2mrScriptPathSighash, SIGHASH_DEFAULT } from './sighash.js';
import { tapBranchHash, tapLeafHash } from './tagged.js';
import { DEFAULT_LEAF_VERSION, TRIPWIRED_LEAF_VERSION } from './tree.js';
import type { Transaction } from './tx.js';
import { assertLockFieldsUint32, LOCKTIME_THRESHOLD, SEQUENCE_FINAL } from './tx.js';
import { assembleScriptPathWitness } from './witness.js';

/** Byte 0xf0: OP_SUCCESS240 everywhere except in an executed P2MR leaf once the rules are active. */
export const OP_CHECKMLDSA44 = 0xf0;

export const MLDSA44_PUBLIC_KEY_SIZE = 1312;
export const MLDSA44_SECRET_KEY_SIZE = 2560;
export const MLDSA44_SIGNATURE_SIZE = 2420;
export const MLDSA44_SEED_SIZE = 32;
/** The public key is pushed by the leaf in three chunks. */
export const MLDSA44_PUBLIC_KEY_CHUNK_SIZES: readonly number[] = [520, 520, 272];
/** The signature travels in five witness elements; the last one is 341 bytes with a hash type. */
export const MLDSA44_SIGNATURE_CHUNK_SIZES: readonly number[] = [520, 520, 520, 520, 340];
/** key_version of the signature message; BIP-342 signatures use 0. */
export const MLDSA44_KEY_VERSION = 0x01;
/** FIPS 204 context string of every signature this opcode checks. */
export const MLDSA44_CONTEXT: Uint8Array = new TextEncoder().encode('P2MR/MLDSA44/EXP0');
/** The leaf next to the template leaf: `OP_RETURN`, which can only fail. */
export const MLDSA44_FAIL_LEAF_SCRIPT: Uint8Array = Uint8Array.of(0x6a);
/** A wallet hands out addresses only once its tip is at least this many blocks past H. */
export const MLDSA44_ACTIVATION_MARGIN = 6;

/** TapLeaf hash of the fail leaf, the one sibling of a template leaf. */
const FAIL_LEAF_HASH = tapLeafHash(MLDSA44_FAIL_LEAF_SCRIPT, DEFAULT_LEAF_VERSION);

/** Exact lengths of the two templates. */
const S1_SIZE = 3 + 520 + 3 + 520 + 3 + 272 + 1;
const S2_SIZE = S1_SIZE + 1 + 1 + 32 + 1;
/** OP_PUSHDATA2 with a little-endian length of 520 and of 272. */
const PUSH_520 = Uint8Array.of(0x4d, 0x08, 0x02);
const PUSH_272 = Uint8Array.of(0x4d, 0x10, 0x01);
const OP_VERIFY = 0x69;
const OP_PUSHBYTES_32 = 0x20;
const OP_CHECKSIG = 0xac;

/** Hash types BIP-341 allows to appear explicitly; an explicit 0x00 is invalid. */
export const EXPLICIT_HASH_TYPES: ReadonlySet<number> = new Set([0x01, 0x02, 0x03, 0x81, 0x82, 0x83]);

/** Leaf versions in which a node executes OP_CHECKMLDSA44: 0xC0, and 0xe0 once the tripwire rules are active. */
const MLDSA44_LEAF_VERSIONS: ReadonlySet<number> = new Set([DEFAULT_LEAF_VERSION, TRIPWIRED_LEAF_VERSION]);

export type Mldsa44Template = 'S1' | 'S2';

function assertPublicKey(publicKey: Uint8Array): void {
  assert(
    publicKey.length === MLDSA44_PUBLIC_KEY_SIZE,
    'MLDSA44_INVALID_PUBLIC_KEY',
    `an ML-DSA-44 public key is ${MLDSA44_PUBLIC_KEY_SIZE} bytes, got ${publicKey.length}`,
  );
}

export function assertXonly(xonlyPubkey: Uint8Array): void {
  assert(
    xonlyPubkey.length === 32,
    'INVALID_XONLY_PUBKEY',
    `an x-only public key is 32 bytes, got ${xonlyPubkey.length}`,
  );
}

function assertMessage(message: Uint8Array): void {
  assert(
    message.length === 32,
    'MLDSA44_INVALID_MESSAGE',
    `an OP_CHECKMLDSA44 signature signs a 32-byte signature message, got ${message.length} bytes`,
  );
}

/**
 * Leaf S1 for an ML-DSA-44 public key, or S2 when an x-only key is given as well.
 *
 * S2 requires both an ML-DSA-44 and a BIP-340 signature; there is no path with only one of them.
 */
export function buildMldsa44LeafScript(publicKey: Uint8Array, xonlyPubkey?: Uint8Array): Uint8Array {
  assertPublicKey(publicKey);
  const s1 = concatBytes(
    PUSH_520,
    publicKey.subarray(0, 520),
    PUSH_520,
    publicKey.subarray(520, 1040),
    PUSH_272,
    publicKey.subarray(1040),
    Uint8Array.of(OP_CHECKMLDSA44),
  );
  if (xonlyPubkey === undefined) return s1;
  assertXonly(xonlyPubkey);
  return concatBytes(
    s1,
    Uint8Array.of(OP_VERIFY, OP_PUSHBYTES_32),
    xonlyPubkey,
    Uint8Array.of(OP_CHECKSIG),
  );
}

export interface ParsedMldsa44Leaf {
  readonly template: Mldsa44Template;
  readonly publicKey: Uint8Array;
  /** The x-only key of S2; null for S1. */
  readonly xonlyPubkey: Uint8Array | null;
}

function startsAt(script: Uint8Array, offset: number, bytes: Uint8Array): boolean {
  return bytesEqual(script.subarray(offset, offset + bytes.length), bytes);
}

/**
 * Recognize S1 and S2 byte for byte, as node policy does; anything else, including a script that
 * merely contains the opcode, is null.
 */
export function parseMldsa44LeafScript(script: Uint8Array): ParsedMldsa44Leaf | null {
  if (script.length !== S1_SIZE && script.length !== S2_SIZE) return null;
  if (
    !startsAt(script, 0, PUSH_520) ||
    !startsAt(script, 523, PUSH_520) ||
    !startsAt(script, 1046, PUSH_272) ||
    script[S1_SIZE - 1] !== OP_CHECKMLDSA44
  ) {
    return null;
  }
  const publicKey = concatBytes(
    script.subarray(3, 523),
    script.subarray(526, 1046),
    script.subarray(1049, S1_SIZE - 1),
  );
  if (script.length === S1_SIZE) return { template: 'S1', publicKey, xonlyPubkey: null };
  if (
    script[S1_SIZE] !== OP_VERIFY ||
    script[S1_SIZE + 1] !== OP_PUSHBYTES_32 ||
    script[S2_SIZE - 1] !== OP_CHECKSIG
  ) {
    return null;
  }
  return { template: 'S2', publicKey, xonlyPubkey: script.slice(S1_SIZE + 2, S2_SIZE - 1) };
}

/**
 * The merkle root of the template output: the template leaf and the fail leaf, both version 0xC0 at
 * depth one. Branch hashing sorts the two children, so the order of the leaves does not matter.
 */
export function mldsa44MerkleRoot(publicKey: Uint8Array, xonlyPubkey?: Uint8Array): Uint8Array {
  return tapBranchHash(
    tapLeafHash(buildMldsa44LeafScript(publicKey, xonlyPubkey), DEFAULT_LEAF_VERSION),
    FAIL_LEAF_HASH,
  );
}

export interface Mldsa44OutputMatchParams {
  readonly scriptPubKey: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly xonlyPubkey?: Uint8Array;
}

/**
 * Whether a scriptPubKey commits to exactly the template tree of these keys: two leaves of version
 * 0xC0 at depth one, one of them S1 (or S2 when an x-only key is given) and the other `6a`.
 *
 * Only such outputs can be counted as protected. Any other tree -- a classical leaf next to an
 * ML-DSA-44 leaf, a single leaf, a fail leaf of another leaf version -- has a spending path that
 * needs no ML-DSA-44 signature, or is not one the wallet can vouch for.
 */
export function mldsa44OutputMatches(params: Mldsa44OutputMatchParams): boolean {
  if (!isP2mrScriptPubKey(params.scriptPubKey)) return false;
  return bytesEqual(
    parseP2mrScriptPubKey(params.scriptPubKey),
    mldsa44MerkleRoot(params.publicKey, params.xonlyPubkey),
  );
}

/** What a wallet observed of the chain; null where it could not find out. */
export interface Mldsa44ChainState {
  /** The activation height H the node reports (see `mldsa44ActivationHeight`). */
  readonly activationHeight: number | null;
  /** The height of the tip the wallet observed. */
  readonly tipHeight: number | null;
}

export function isHeight(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

export function buriedHeight(deployments: Record<string, unknown>, name: string): number | null {
  const entry = deployments[name];
  if (typeof entry !== 'object' || entry === null) return null;
  const { type, height } = entry as Record<string, unknown>;
  return type === 'buried' && isHeight(height) ? height : null;
}

/**
 * The height from which the node enforces the rules, from the result of its `getdeploymentinfo`, or
 * null.
 *
 * A block is checked under OP_CHECKMLDSA44 only when both buried deployments, `p2mr` and
 * `p2mr_mldsa44`, are active at its height, so the result is the higher of the two heights. A node
 * whose build does not activate a deployment on its chain does not list it, and the result is null.
 */
export function mldsa44ActivationHeight(deploymentInfo: unknown): number | null {
  if (typeof deploymentInfo !== 'object' || deploymentInfo === null) return null;
  const deployments = (deploymentInfo as Record<string, unknown>)['deployments'];
  if (typeof deployments !== 'object' || deployments === null) return null;
  const p2mr = buriedHeight(deployments as Record<string, unknown>, 'p2mr');
  const mldsa44 = buriedHeight(deployments as Record<string, unknown>, 'p2mr_mldsa44');
  return p2mr === null || mldsa44 === null ? null : Math.max(p2mr, mldsa44);
}

/**
 * Whether a wallet may hand out a template address or build a template output: only once the tip
 * it observed is at least H + 6. Unknown state is a refusal.
 *
 * The rules being possible on a chain is not enough; before H an OP_CHECKMLDSA44 leaf is an
 * OP_SUCCESSx that anyone can spend. The six blocks leave room for a reorganization. When one takes
 * the tip back below H + 6, this turns false again and the wallet stops handing out addresses.
 */
export function mldsa44AddressesAllowed(chain: Mldsa44ChainState): boolean {
  const { activationHeight, tipHeight } = chain;
  if (!isHeight(activationHeight) || !isHeight(tipHeight)) return false;
  return tipHeight >= activationHeight + MLDSA44_ACTIVATION_MARGIN;
}

/** Throw unless `mldsa44AddressesAllowed`. */
export function assertMldsa44AddressesAllowed(chain: Mldsa44ChainState): void {
  if (!isHeight(chain.activationHeight) || !isHeight(chain.tipHeight)) {
    throw new P2mrError(
      'MLDSA44_ACTIVATION_UNKNOWN',
      'the activation height or the tip height is unknown; without them no OP_CHECKMLDSA44 output is built',
    );
  }
  assert(
    mldsa44AddressesAllowed(chain),
    'MLDSA44_NOT_ACTIVE',
    `the tip ${chain.tipHeight} is not yet ${MLDSA44_ACTIVATION_MARGIN} blocks past the activation height ${chain.activationHeight}; ` +
      'until then an OP_CHECKMLDSA44 leaf is spendable by anyone',
  );
}

/**
 * The networks a template output may be built for. The rules only ever activate on the Ark-0 signet
 * and on regtest; on mainnet or testnet a witness v2 output is spendable by anyone.
 */
export type Mldsa44Network = Extract<Network, 'signet' | 'regtest'>;

export const MLDSA44_NETWORKS: ReadonlySet<string> = new Set(['signet', 'regtest']);

export interface CreateMldsa44OutputOptions {
  readonly publicKey: Uint8Array;
  /** Makes the leaf S2, which needs a BIP-340 signature by this key as well. */
  readonly xonlyPubkey?: Uint8Array;
  /** Required, and the network whose node `chain` was read from: `signet` or `regtest`. */
  readonly network: Mldsa44Network;
  /** The output is refused unless the tip is at least H + 6 (see `mldsa44AddressesAllowed`). */
  readonly chain: Mldsa44ChainState;
}

export interface Mldsa44Output extends P2mrOutput {
  readonly template: Mldsa44Template;
  readonly templateLeaf: P2mrLeafOutput;
  readonly failLeaf: P2mrLeafOutput;
}

/**
 * Build the template output: the S1 or S2 leaf and the `6a` fail leaf, both at depth one.
 *
 * `createP2mrOutput` rejects any leaf containing an OP_SUCCESSx, 0xf0 included, and keeps doing so.
 * Here the one leaf with that byte is built from a key by this module, so its OP_SUCCESS check is
 * lifted for this tree only.
 */
export function createMldsa44Output(options: CreateMldsa44OutputOptions): Mldsa44Output {
  assert(
    MLDSA44_NETWORKS.has(options.network as string),
    'MLDSA44_NETWORK_NOT_ALLOWED',
    `template outputs are built for signet or regtest only, got ${String(options.network)}; ` +
      'elsewhere a witness v2 output is spendable by anyone',
  );
  assertMldsa44AddressesAllowed(options.chain);
  const script = buildMldsa44LeafScript(options.publicKey, options.xonlyPubkey);
  const out = createP2mrOutput({
    scriptTree: [
      { script, leafVersion: DEFAULT_LEAF_VERSION },
      { script: MLDSA44_FAIL_LEAF_SCRIPT, leafVersion: DEFAULT_LEAF_VERSION },
    ],
    allowOpSuccess: true,
    network: options.network,
  });
  return {
    ...out,
    template: options.xonlyPubkey === undefined ? 'S1' : 'S2',
    templateLeaf: out.leaves[0] as P2mrLeafOutput,
    failLeaf: out.leaves[1] as P2mrLeafOutput,
  };
}

export interface Mldsa44SighashParams
  extends Omit<P2mrScriptPathSighashParams, 'leafHash' | 'keyVersion' | 'leafScript' | 'leafVersion'> {
  /** The leaf being executed. */
  readonly leafScript: Uint8Array;
  /**
   * Its leaf version: 0xC0, the default, or 0xe0 for the ML-DSA-44 leaf of an S3 output (see
   * tripwire.ts). The TapLeaf hash commits to it, so a signature for one does not verify in the other.
   */
  readonly leafVersion?: number;
}

/**
 * The 32-byte message an OP_CHECKMLDSA44 signature signs: the BIP-341 tapscript signature hash with
 * key_version 1. It commits to the leaf, the hash type, the annex if any and `codeseparatorPosition`.
 *
 * The BIP-340 signature of S2 signs the same message with key_version 0, i.e.
 * `p2mrScriptPathSighash` with the leaf hash of the template leaf.
 */
export function mldsa44Sighash(params: Mldsa44SighashParams): Uint8Array {
  const { leafScript, leafVersion = DEFAULT_LEAF_VERSION, ...rest } = params;
  assert(
    MLDSA44_LEAF_VERSIONS.has(leafVersion),
    'LEAF_VERSION_NOT_ALLOWED',
    `OP_CHECKMLDSA44 is executed in leaves of version 0xc0, and of version 0xe0 once the tripwire rules are active; got ${String(leafVersion)}`,
  );
  return p2mrScriptPathSighash({
    ...rest,
    leafHash: tapLeafHash(leafScript, leafVersion),
    keyVersion: MLDSA44_KEY_VERSION,
  });
}

export interface Mldsa44KeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

/**
 * An ML-DSA-44 key pair: ML-DSA.KeyGen_internal of FIPS 204 on a 32-byte seed, or on a random seed
 * when none is given. Whoever holds the seed holds the key.
 */
export function mldsa44Keygen(seed?: Uint8Array): Mldsa44KeyPair {
  if (seed !== undefined) {
    assert(
      seed.length === MLDSA44_SEED_SIZE,
      'MLDSA44_INVALID_SEED',
      `an ML-DSA-44 seed is ${MLDSA44_SEED_SIZE} bytes, got ${seed.length}`,
    );
  }
  const { publicKey, secretKey } = ml_dsa44.keygen(seed);
  return { publicKey, secretKey };
}

export interface Mldsa44SignOptions {
  /**
   * 32 bytes of signing randomness, or `false` for the deterministic variant of FIPS 204. By default
   * fresh randomness is drawn (the hedged variant FIPS 204 recommends). Verification is the same for
   * both.
   */
  readonly extraEntropy?: Uint8Array | false;
}

/** Sign a 32-byte signature message with pure ML-DSA-44 and this opcode's context string. */
export function mldsa44Sign(
  secretKey: Uint8Array,
  message: Uint8Array,
  options: Mldsa44SignOptions = {},
): Uint8Array {
  assert(
    secretKey.length === MLDSA44_SECRET_KEY_SIZE,
    'MLDSA44_INVALID_SECRET_KEY',
    `an ML-DSA-44 secret key is ${MLDSA44_SECRET_KEY_SIZE} bytes, got ${secretKey.length}`,
  );
  assertMessage(message);
  return ml_dsa44.sign(message, secretKey, {
    context: MLDSA44_CONTEXT,
    ...(options.extraEntropy === undefined ? {} : { extraEntropy: options.extraEntropy }),
  });
}

/**
 * Verify a 2420-byte signature over a 32-byte message with pure ML-DSA-44 and this opcode's context
 * string. A key, message or signature of another size is invalid, not an error.
 */
export function mldsa44Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (
    publicKey.length !== MLDSA44_PUBLIC_KEY_SIZE ||
    message.length !== 32 ||
    signature.length !== MLDSA44_SIGNATURE_SIZE
  ) {
    return false;
  }
  return ml_dsa44.verify(signature, message, publicKey, { context: MLDSA44_CONTEXT });
}

export interface SignMldsa44InputParams extends Mldsa44SighashParams, Mldsa44SignOptions {
  readonly secretKey: Uint8Array;
}

/**
 * Sign an input that spends a template leaf, or with `leafVersion` 0xe0 the ML-DSA-44 leaf of an S3
 * output. The result is 2420 bytes, or 2421 with the hash type appended when it is not
 * SIGHASH_DEFAULT (an explicit 0x00 is invalid, so it is never appended).
 */
export function signMldsa44Input(params: SignMldsa44InputParams): Uint8Array {
  const { secretKey, extraEntropy, ...sighashParams } = params;
  const message = mldsa44Sighash(sighashParams);
  const signature = mldsa44Sign(
    secretKey,
    message,
    extraEntropy === undefined ? {} : { extraEntropy },
  );
  const hashType = params.hashType ?? SIGHASH_DEFAULT;
  return hashType === SIGHASH_DEFAULT ? signature : concatBytes(signature, Uint8Array.of(hashType));
}

/**
 * Cut a signature into its five witness elements: 520, 520, 520, 520 and 340 bytes, or 341 when it
 * ends in an explicit hash type, which must then be one BIP-341 allows.
 */
export function splitMldsa44Signature(signature: Uint8Array): Uint8Array[] {
  assert(
    signature.length === MLDSA44_SIGNATURE_SIZE || signature.length === MLDSA44_SIGNATURE_SIZE + 1,
    'MLDSA44_INVALID_SIGNATURE_SIZE',
    `an OP_CHECKMLDSA44 signature is ${MLDSA44_SIGNATURE_SIZE} bytes, or ${MLDSA44_SIGNATURE_SIZE + 1} with a hash type, got ${signature.length}`,
  );
  if (signature.length === MLDSA44_SIGNATURE_SIZE + 1) {
    const hashType = signature[MLDSA44_SIGNATURE_SIZE] as number;
    assert(
      EXPLICIT_HASH_TYPES.has(hashType),
      'INVALID_HASH_TYPE',
      `explicit hash type 0x${hashType.toString(16)} is invalid; allowed are 0x01-0x03 and 0x81-0x83`,
    );
  }
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < 4; i++) chunks.push(signature.slice(520 * i, 520 * (i + 1)));
  chunks.push(signature.slice(2080));
  return chunks;
}

export interface AssembleMldsa44WitnessOptions {
  /** The ML-DSA-44 signature, 2420 bytes or 2421 with a hash type (see `signMldsa44Input`). */
  readonly signature: Uint8Array;
  /** S1 or S2, byte for byte. */
  readonly leafScript: Uint8Array;
  /** The control block of the template leaf: 33 bytes, leaf version 0xC0, one sibling (the fail leaf). */
  readonly controlBlock: Uint8Array;
  /** S2 only: the BIP-340 signature (64 bytes, or 65 with a hash type) for its OP_CHECKSIG. */
  readonly schnorrSignature?: Uint8Array;
}

/**
 * The witness of a template spend: [BIP-340 signature for S2], five signature chunks, the leaf and
 * the control block. No annex: node policy rejects one.
 */
export function assembleMldsa44Witness(options: AssembleMldsa44WitnessOptions): Uint8Array[] {
  const parsed = parseMldsa44LeafScript(options.leafScript);
  if (parsed === null) {
    throw new P2mrError(
      'MLDSA44_NOT_A_TEMPLATE',
      'the leaf is neither S1 nor S2; other scripts with OP_CHECKMLDSA44 are not relayed and may need no signature',
    );
  }
  const cb = parseControlBlock(options.controlBlock);
  assert(
    cb.leafVersion === DEFAULT_LEAF_VERSION && cb.m === 1,
    'MLDSA44_INVALID_CONTROL_BLOCK',
    `a template leaf sits at depth one with leaf version 0xc0, but the control block has depth ${cb.m} and leaf version 0x${cb.leafVersion.toString(16)}`,
  );
  assert(
    bytesEqual(cb.merklePath[0] as Uint8Array, FAIL_LEAF_HASH),
    'MLDSA44_INVALID_CONTROL_BLOCK',
    'the sibling in the control block is not the fail leaf 6a; this is not the template tree',
  );
  const stack: Uint8Array[] = [];
  if (parsed.template === 'S2') {
    const schnorr = options.schnorrSignature;
    assert(
      schnorr !== undefined && (schnorr.length === 64 || schnorr.length === 65),
      'MLDSA44_INVALID_WITNESS',
      'an S2 spend needs a BIP-340 signature of 64 or 65 bytes below the ML-DSA-44 signature',
    );
    if (schnorr.length === 65) {
      const hashType = schnorr[64] as number;
      assert(
        EXPLICIT_HASH_TYPES.has(hashType),
        'INVALID_HASH_TYPE',
        `explicit hash type 0x${hashType.toString(16)} of the BIP-340 signature is invalid; allowed are 0x01-0x03 and 0x81-0x83`,
      );
    }
    stack.push(schnorr);
  } else {
    assert(
      options.schnorrSignature === undefined,
      'MLDSA44_INVALID_WITNESS',
      'an S1 spend takes no BIP-340 signature',
    );
  }
  stack.push(...splitMldsa44Signature(options.signature));
  return assembleScriptPathWitness({
    stack,
    leafScript: options.leafScript,
    controlBlock: options.controlBlock,
  });
}

export type Mldsa44ProtectionStatus = 'protected' | 'pending' | 'unprotected';

export interface Mldsa44ProtectionParams extends Mldsa44OutputMatchParams {
  /** Height of the block that confirmed the output on the current chain; null while unconfirmed. */
  readonly confirmationHeight: number | null;
  /** The activation height H; null when unknown. */
  readonly activationHeight: number | null;
}

/**
 * The status of a received output:
 * - `unprotected` unless the output commits to exactly this wallet's template tree
 *   (`mldsa44OutputMatches`), at any height;
 * - `pending` while unconfirmed: not yet protected, and not counted as protected;
 * - `protected` once confirmed at or above H: every spend of it comes after H, under the rules;
 * - `unprotected` when confirmed below H (which takes a deep reorganization) or when H is unknown.
 *
 * Compute it again after a reorganization: the same output can go from protected to pending and
 * back, or confirm at another height.
 */
export function mldsa44ProtectionStatus(params: Mldsa44ProtectionParams): Mldsa44ProtectionStatus {
  if (!mldsa44OutputMatches(params)) return 'unprotected';
  if (params.confirmationHeight === null) return 'pending';
  const { activationHeight, confirmationHeight } = params;
  if (!isHeight(confirmationHeight)) return 'unprotected';
  return isHeight(activationHeight) && confirmationHeight >= activationHeight
    ? 'protected'
    : 'unprotected';
}

/**
 * A funding transaction the wallet builds itself, with nLockTime set to H so that it confirms no
 * earlier than H + 1, even after a reorganization. Apply it before signing: signatures commit to
 * the lock time.
 *
 * nLockTime applies only when at least one input has an nSequence below 0xffffffff, so a
 * transaction without such an input is refused rather than silently left unlocked.
 */
export function withMldsa44FundingLockTime(tx: Transaction, activationHeight: number): Transaction {
  assert(
    isHeight(activationHeight) && activationHeight < LOCKTIME_THRESHOLD,
    'INVALID_LOCKTIME',
    `the activation height must be a block height below ${LOCKTIME_THRESHOLD}, got ${String(activationHeight)}`,
  );
  assertLockFieldsUint32(tx);
  assert(
    tx.inputs.some((input) => input.sequence !== SEQUENCE_FINAL),
    'MLDSA44_FUNDING_SEQUENCE_FINAL',
    'every input has nSequence 0xffffffff, which turns the lock time off; give at least one input a lower nSequence',
  );
  return { ...tx, locktime: activationHeight };
}
