/**
 * Wallet side of the tripwired leaves, leaf version 0xe0, an experiment of the Ark-0 test signet.
 *
 * The leaf version is not part of BIP-360. From an activation height H3 fixed in its build, a node
 * with the M3 patch series executes a P2MR leaf of version 0xe0 as it executes a leaf of version
 * 0xC0, OP_CHECKMLDSA44 included, with one difference: once either of two designated tripwire
 * outputs is no longer in the UTXO set, from the next block on, OP_CHECKSIG, OP_CHECKSIGVERIFY and
 * OP_CHECKSIGADD in these leaves fail the script whenever they meet a 32-byte key and a non-empty
 * signature, valid or not. Leaves of version 0xC0 are not affected, and before H3 a leaf of version
 * 0xe0 is not executed at all: anyone can spend it.
 *
 * The one template built here, S3, is a tree of exactly two leaves of version 0xe0, both at depth
 * one, either of which spends the output:
 *
 *   Schnorr leaf:    20 <32-byte x-only key> ac        (<key> OP_CHECKSIG)
 *   ML-DSA-44 leaf:  S1 of mldsa44.ts, byte for byte
 *   control block:   e1 <TapLeaf hash of the other leaf, version 0xe0>
 *
 * The Schnorr leaf is the cheaper one while the checks are on; the ML-DSA-44 leaf keeps working
 * after they are off. No template puts both checks in one leaf: once the checks are off such a leaf
 * cannot be spent at all. No tree has a single leaf either: with m = 0 the leaf is never executed.
 *
 * The signature messages are those of leaves of version 0xC0, with the TapLeaf hash of the leaf at
 * version 0xe0. That hash commits to the leaf version, so a signature made for a leaf of one version
 * does not verify in the same leaf of the other. A funding transaction the wallet builds itself gets
 * its lock time from `withMldsa44FundingLockTime(tx, H3)`.
 */
import { bytesEqual, concatBytes } from './bytes.js';
import { encodeControlBlock } from './controlBlock.js';
import { assert, P2mrError } from './errors.js';
import type { Mldsa44Network } from './mldsa44.js';
import {
  assertXonly,
  buildMldsa44LeafScript,
  buriedHeight,
  EXPLICIT_HASH_TYPES,
  isHeight,
  MLDSA44_ACTIVATION_MARGIN,
  MLDSA44_NETWORKS,
  mldsa44ActivationHeight,
  mldsa44Sighash,
  splitMldsa44Signature,
} from './mldsa44.js';
import type { P2mrLeafOutput, P2mrOutput } from './output.js';
import { createP2mrOutput, isP2mrScriptPubKey, parseP2mrScriptPubKey } from './output.js';
import type { P2mrScriptPathSighashParams } from './sighash.js';
import { p2mrScriptPathSighash, TAPSCRIPT_KEY_VERSION } from './sighash.js';
import { tapBranchHash, tapLeafHash } from './tagged.js';
import { TRIPWIRED_LEAF_VERSION } from './tree.js';
import { assembleScriptPathWitness } from './witness.js';

/** The keys of an S3 output: one for each leaf. */
export interface TripwiredKeys {
  /** The 32-byte x-only key of the Schnorr leaf. */
  readonly xonlyPubkey: Uint8Array;
  /** The 1312-byte ML-DSA-44 public key of the S1 leaf. */
  readonly publicKey: Uint8Array;
}

/** Which leaf of an S3 output a spend executes. */
export type TripwiredPath = 'schnorr' | 'mldsa44';

interface LeafScripts {
  readonly schnorr: Uint8Array;
  readonly mldsa44: Uint8Array;
}

/** The two leaf scripts of S3, once both keys are the right size. */
function leafScripts(keys: TripwiredKeys): LeafScripts {
  assertXonly(keys.xonlyPubkey);
  return {
    schnorr: concatBytes(Uint8Array.of(0x20), keys.xonlyPubkey, Uint8Array.of(0xac)),
    mldsa44: buildMldsa44LeafScript(keys.publicKey),
  };
}

/** The control block of an S3 leaf: version 0xe0, with the other leaf as its one sibling. */
function controlBlockNextTo(sibling: Uint8Array): Uint8Array {
  return encodeControlBlock(TRIPWIRED_LEAF_VERSION, [tapLeafHash(sibling, TRIPWIRED_LEAF_VERSION)]);
}

function invalidPath(path: never): never {
  throw new P2mrError(
    'TRIPWIRED_INVALID_PATH',
    `an S3 output is spent through its 'schnorr' or its 'mldsa44' leaf, got ${String(path)}`,
  );
}

/**
 * The merkle root of the S3 output of these keys. Branch hashing sorts the two children, so the
 * order of the leaves does not matter.
 */
export function tripwiredMerkleRoot(keys: TripwiredKeys): Uint8Array {
  const { schnorr, mldsa44 } = leafScripts(keys);
  return tapBranchHash(
    tapLeafHash(schnorr, TRIPWIRED_LEAF_VERSION),
    tapLeafHash(mldsa44, TRIPWIRED_LEAF_VERSION),
  );
}

export interface TripwiredOutputMatchParams extends TripwiredKeys {
  readonly scriptPubKey: Uint8Array;
}

/**
 * Whether a scriptPubKey commits to exactly the S3 tree of these keys: two leaves of version 0xe0 at
 * depth one, one of them exactly `<x-only key> OP_CHECKSIG` and the other exactly S1.
 *
 * A wallet reports nothing about an output this does not hold for. Any other tree has another root:
 * a third leaf, a leaf of another version, a script one byte off, a single leaf, other keys.
 */
export function tripwiredOutputMatches(params: TripwiredOutputMatchParams): boolean {
  if (!isP2mrScriptPubKey(params.scriptPubKey)) return false;
  return bytesEqual(parseP2mrScriptPubKey(params.scriptPubKey), tripwiredMerkleRoot(params));
}

/**
 * H3, the height from which the node checks the leaves of an S3 output, from the result of its
 * `getdeploymentinfo`, or null.
 *
 * The leaves are executed only where the buried deployment `p2mr_tripwire` is active, and the
 * ML-DSA-44 leaf is checked only where `p2mr` and `p2mr_mldsa44` are, so the result is the highest
 * of the three heights. A node that does not list one of them gives null.
 */
export function tripwireActivationHeight(deploymentInfo: unknown): number | null {
  const mldsa44 = mldsa44ActivationHeight(deploymentInfo);
  if (mldsa44 === null) return null;
  // mldsa44ActivationHeight found an object `deployments` in it
  const { deployments } = deploymentInfo as { deployments: Record<string, unknown> };
  const tripwire = buriedHeight(deployments, 'p2mr_tripwire');
  return tripwire === null ? null : Math.max(mldsa44, tripwire);
}

/** What a wallet observed of the chain; null where it could not find out. */
export interface TripwireChainState {
  /**
   * H3, as `tripwireActivationHeight` reads it. It is not the activation height of OP_CHECKMLDSA44,
   * which comes earlier; hence a field name of its own.
   */
  readonly tripwireHeight: number | null;
  /** The height of the tip the wallet observed. */
  readonly tipHeight: number | null;
}

/**
 * Whether a wallet may hand out an S3 address or build an S3 output: only once the tip it observed
 * is at least H3 + 6, the margin of the template outputs of mldsa44.ts. Unknown state is a refusal.
 *
 * Before H3 a leaf of version 0xe0 is not executed and anyone can spend it; the six blocks leave room
 * for a reorganization. When one takes the tip back below H3 + 6, this turns false again.
 */
export function tripwiredAddressesAllowed(chain: TripwireChainState): boolean {
  const { tripwireHeight, tipHeight } = chain;
  if (!isHeight(tripwireHeight) || !isHeight(tipHeight)) return false;
  return tipHeight >= tripwireHeight + MLDSA44_ACTIVATION_MARGIN;
}

/** Throw unless `tripwiredAddressesAllowed`. */
export function assertTripwiredAddressesAllowed(chain: TripwireChainState): void {
  if (!isHeight(chain.tripwireHeight) || !isHeight(chain.tipHeight)) {
    throw new P2mrError(
      'TRIPWIRED_ACTIVATION_UNKNOWN',
      'the tripwire activation height or the tip height is unknown; without them no S3 output is built',
    );
  }
  assert(
    tripwiredAddressesAllowed(chain),
    'TRIPWIRED_NOT_ACTIVE',
    `the tip ${chain.tipHeight} is not yet ${MLDSA44_ACTIVATION_MARGIN} blocks past the tripwire activation height ${chain.tripwireHeight}; ` +
      'before that height a leaf of version 0xe0 is spendable by anyone',
  );
}

/** The networks an S3 output may be built for: those of the template outputs of mldsa44.ts. */
export type TripwiredNetwork = Mldsa44Network;

export interface CreateTripwiredOutputOptions extends TripwiredKeys {
  /** Required, and the network whose node `chain` was read from: `signet` or `regtest`. */
  readonly network: TripwiredNetwork;
  /** The output is refused unless the tip is at least H3 + 6 (see `tripwiredAddressesAllowed`). */
  readonly chain: TripwireChainState;
}

export interface TripwiredOutput extends P2mrOutput {
  readonly schnorrLeaf: P2mrLeafOutput;
  readonly mldsa44Leaf: P2mrLeafOutput;
}

/**
 * Build the S3 output of these keys.
 *
 * `createP2mrOutput` refuses leaf version 0xe0, like every version other than 0xC0, and refuses the
 * byte 0xf0 of S1, like every OP_SUCCESSx; it keeps doing so. Both are lifted here for this one tree,
 * whose two leaves this module builds from the keys.
 */
export function createTripwiredOutput(options: CreateTripwiredOutputOptions): TripwiredOutput {
  assert(
    MLDSA44_NETWORKS.has(options.network as string),
    'TRIPWIRED_NETWORK_NOT_ALLOWED',
    `S3 outputs are built for signet or regtest only, got ${String(options.network)}; ` +
      'elsewhere a witness v2 output is spendable by anyone',
  );
  assertTripwiredAddressesAllowed(options.chain);
  const { schnorr, mldsa44 } = leafScripts(options);
  const out = createP2mrOutput({
    scriptTree: [
      { script: schnorr, leafVersion: TRIPWIRED_LEAF_VERSION },
      { script: mldsa44, leafVersion: TRIPWIRED_LEAF_VERSION },
    ],
    allowUnsafeLeafVersion: true,
    allowOpSuccess: true,
    network: options.network,
  });
  return {
    ...out,
    schnorrLeaf: out.leaves[0] as P2mrLeafOutput,
    mldsa44Leaf: out.leaves[1] as P2mrLeafOutput,
  };
}

export type TripwiredOutputStatus = 'constrained' | 'pending' | 'unprotected';

export interface TripwiredOutputStatusParams extends TripwiredOutputMatchParams {
  /** Height of the block that confirmed the output on the current chain; null while unconfirmed. */
  readonly confirmationHeight: number | null;
  /** H3; null when unknown. */
  readonly tripwireHeight: number | null;
}

/**
 * The status of a received output:
 * - `unprotected` unless the output commits to exactly the S3 tree of this wallet's keys
 *   (`tripwiredOutputMatches`), at any height;
 * - `pending` while unconfirmed;
 * - `constrained` once confirmed at or above H3: every spend of it comes after H3, under the
 *   tripwire rules, so its Schnorr leaf stops working once the checks are off and its ML-DSA-44
 *   leaf does not;
 * - `unprotected` when confirmed below H3 (which takes a deep reorganization) or when H3 is unknown.
 *
 * Compute it again after a reorganization: the same output can go from constrained to pending and
 * back, or confirm at another height.
 */
export function tripwiredOutputStatus(params: TripwiredOutputStatusParams): TripwiredOutputStatus {
  if (!tripwiredOutputMatches(params)) return 'unprotected';
  if (params.confirmationHeight === null) return 'pending';
  const { tripwireHeight, confirmationHeight } = params;
  if (!isHeight(confirmationHeight)) return 'unprotected';
  return isHeight(tripwireHeight) && confirmationHeight >= tripwireHeight
    ? 'constrained'
    : 'unprotected';
}

export interface TripwiredSighashParams
  extends TripwiredKeys,
    Omit<P2mrScriptPathSighashParams, 'leafHash' | 'keyVersion'> {
  readonly path: TripwiredPath;
}

/**
 * The 32-byte message a spend of an S3 output signs, over the TapLeaf hash of the leaf at version
 * 0xe0. For the Schnorr leaf it is the BIP-342 message (key_version 0), for a BIP-340 signature made
 * by the caller; for the ML-DSA-44 leaf it is the message of `mldsa44Sighash` (key_version 1),
 * which `signMldsa44Input` signs when given `leafVersion` 0xe0.
 */
export function tripwiredSighash(params: TripwiredSighashParams): Uint8Array {
  const { path, xonlyPubkey, publicKey, ...rest } = params;
  const leaves = leafScripts({ xonlyPubkey, publicKey });
  switch (path) {
    case 'schnorr':
      return p2mrScriptPathSighash({
        ...rest,
        leafHash: tapLeafHash(leaves.schnorr, TRIPWIRED_LEAF_VERSION),
        keyVersion: TAPSCRIPT_KEY_VERSION,
      });
    case 'mldsa44':
      return mldsa44Sighash({
        ...rest,
        leafScript: leaves.mldsa44,
        leafVersion: TRIPWIRED_LEAF_VERSION,
      });
    default:
      return invalidPath(path);
  }
}

export interface AssembleTripwiredWitnessOptions extends TripwiredKeys {
  readonly path: TripwiredPath;
  /**
   * For `schnorr` the BIP-340 signature, 64 bytes or 65 with an explicit hash type; for `mldsa44` the
   * ML-DSA-44 signature, 2420 bytes or 2421 with an explicit hash type (see `signMldsa44Input`).
   */
  readonly signature: Uint8Array;
}

/**
 * The witness of a spend of an S3 output: the signature (an ML-DSA-44 one in its five chunks), the
 * leaf and its control block. The leaf and its sibling are built from both keys, so they are exactly
 * those of the S3 tree. No annex: node policy rejects one.
 */
export function assembleTripwiredWitness(options: AssembleTripwiredWitnessOptions): Uint8Array[] {
  const { schnorr, mldsa44 } = leafScripts(options);
  const { path, signature } = options;
  switch (path) {
    case 'schnorr': {
      assert(
        signature.length === 64 || signature.length === 65,
        'TRIPWIRED_INVALID_SIGNATURE_SIZE',
        `a BIP-340 signature is 64 bytes, or 65 with a hash type, got ${signature.length}`,
      );
      if (signature.length === 65) {
        const hashType = signature[64] as number;
        assert(
          EXPLICIT_HASH_TYPES.has(hashType),
          'INVALID_HASH_TYPE',
          `explicit hash type 0x${hashType.toString(16)} of the BIP-340 signature is invalid; allowed are 0x01-0x03 and 0x81-0x83`,
        );
      }
      return assembleScriptPathWitness({
        stack: [signature],
        leafScript: schnorr,
        controlBlock: controlBlockNextTo(mldsa44),
      });
    }
    case 'mldsa44':
      return assembleScriptPathWitness({
        stack: splitMldsa44Signature(signature),
        leafScript: mldsa44,
        controlBlock: controlBlockNextTo(schnorr),
      });
    default:
      return invalidPath(path);
  }
}
