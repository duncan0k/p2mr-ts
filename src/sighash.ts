import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, serializeVarBytes, u32le, u64le } from './bytes.js';
import { assert } from './errors.js';
import { isP2mrScriptPubKey } from './output.js';
import { tapSighash } from './tagged.js';
import type { SpentOutput, Transaction } from './tx.js';
import { serializeOutPoint, serializeTxOutput } from './tx.js';
import { ANNEX_PREFIX } from './witness.js';

export const SIGHASH_DEFAULT = 0x00;
export const SIGHASH_ALL = 0x01;
export const SIGHASH_NONE = 0x02;
export const SIGHASH_SINGLE = 0x03;
export const SIGHASH_ANYONECANPAY = 0x80;

/** Every hash_type BIP-341 allows. 0x80 on its own is invalid. */
const VALID_HASH_TYPES: ReadonlySet<number> = new Set([0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83]);

/** Sentinel used when no OP_CODESEPARATOR has been executed. */
export const NO_CODESEPARATOR = 0xffffffff;

/** The tapscript key_version; it is neither the witness version nor the leaf version. */
export const TAPSCRIPT_KEY_VERSION = 0x00;

export interface TaprootSighashParams {
  readonly tx: Transaction;
  readonly inputIndex: number;
  /** Spent outputs in one-to-one correspondence with tx.inputs. */
  readonly spentOutputs: readonly SpentOutput[];
  /** Defaults to SIGHASH_DEFAULT (0x00). */
  readonly hashType?: number;
  /** Optional annex, which must start with 0x50. */
  readonly annex?: Uint8Array;
  /** 0 = key path, 1 = tapscript/P2MR script path. Defaults to 1. */
  readonly extFlag?: 0 | 1;
  /** Required when extFlag=1: the TapLeaf hash of the leaf being executed. */
  readonly leafHash?: Uint8Array;
  /** Defaults to 0x00. */
  readonly keyVersion?: number;
  /** Defaults to 0xffffffff (no OP_CODESEPARATOR executed). */
  readonly codeseparatorPosition?: number;
}

function validate(params: TaprootSighashParams): {
  hashType: number;
  extFlag: 0 | 1;
  annex: Uint8Array | null;
} {
  const { tx, inputIndex, spentOutputs } = params;
  const hashType = params.hashType ?? SIGHASH_DEFAULT;
  const extFlag: 0 | 1 = params.extFlag ?? 1;

  // TypeScript types only hold at compile time; a JavaScript caller or `as any` passing 2 produces
  // spend_type=4 without appending ext, silently yielding an off-spec digest. BIP-342 allows only
  // ext_flag 0 or 1.
  assert(
    (extFlag as number) === 0 || (extFlag as number) === 1,
    'INVALID_EXT_FLAG',
    `ext_flag must be 0 (key path) or 1 (script path), got ${String(extFlag)}`,
  );
  assert(
    VALID_HASH_TYPES.has(hashType),
    'INVALID_HASH_TYPE',
    `invalid hash_type 0x${hashType.toString(16)}; valid values are 0x00/0x01/0x02/0x03/0x81/0x82/0x83`,
  );
  assert(
    spentOutputs.length === tx.inputs.length,
    'SPENT_OUTPUTS_MISMATCH',
    `spentOutputs count ${spentOutputs.length} does not match the input count ${tx.inputs.length}`,
  );
  assert(
    Number.isInteger(inputIndex) && inputIndex >= 0 && inputIndex < tx.inputs.length,
    'INVALID_INPUT_INDEX',
    `input index ${inputIndex} out of range (${tx.inputs.length} inputs in total)`,
  );
  if ((hashType & 3) === SIGHASH_SINGLE) {
    assert(
      inputIndex < tx.outputs.length,
      'SIGHASH_SINGLE_WITHOUT_OUTPUT',
      `SIGHASH_SINGLE requires an output at the same index, but input index ${inputIndex} >= output count ${tx.outputs.length}`,
    );
  }

  let annex: Uint8Array | null = null;
  if (params.annex !== undefined) {
    assert(
      params.annex.length > 0 && params.annex[0] === ANNEX_PREFIX,
      'INVALID_ANNEX',
      'annex must be non-empty and start with 0x50',
    );
    annex = params.annex;
  }

  if (extFlag === 1) {
    assert(params.leafHash !== undefined, 'MISSING_LEAF_HASH', 'leafHash is required when extFlag=1');
    assert(
      params.leafHash.length === 32,
      'INVALID_LEAF_HASH',
      `leafHash must be 32 bytes, got ${params.leafHash.length}`,
    );
  }

  const keyVersion = params.keyVersion ?? TAPSCRIPT_KEY_VERSION;
  assert(
    Number.isInteger(keyVersion) && keyVersion >= 0 && keyVersion <= 0xff,
    'INVALID_KEY_VERSION',
    `key_version must be an integer in 0..255, got ${String(keyVersion)}`,
  );

  const codesep = params.codeseparatorPosition ?? NO_CODESEPARATOR;
  assert(
    Number.isInteger(codesep) && codesep >= 0 && codesep <= 0xffffffff,
    'INVALID_CODESEPARATOR_POSITION',
    `codesep_pos must be a uint32, got ${String(codesep)}`,
  );

  return { hashType, extFlag, annex };
}

/**
 * Compute the complete signature hash preimage per BIP-341 / BIP-342.
 *
 * The return value **includes** the leading 0x00 epoch byte, i.e. `0x00 ‖ SigMsg(hash_type, ext_flag) ‖ ext`,
 * matching the convention of the `sigMsg` field in the upstream BIP-341 wallet vectors.
 *
 * The digest commits to the **actual** scriptPubKey of each spent output. For P2MR that is
 * `OP_2 <root>`, which must not be substituted with an `OP_1 <root>` form.
 */
export function taprootSigMsg(params: TaprootSighashParams): Uint8Array {
  const { hashType, extFlag, annex } = validate(params);
  const { tx, inputIndex, spentOutputs } = params;
  const input = tx.inputs[inputIndex] as NonNullable<(typeof tx.inputs)[number]>;
  const spent = spentOutputs[inputIndex] as SpentOutput;

  const parts: Uint8Array[] = [
    Uint8Array.of(0x00), // sighash epoch
    Uint8Array.of(hashType),
    u32le(tx.version),
    u32le(tx.locktime),
  ];

  const anyoneCanPay = (hashType & SIGHASH_ANYONECANPAY) !== 0;
  if (!anyoneCanPay) {
    parts.push(sha256(concatBytes(...tx.inputs.map(serializeOutPoint))));
    parts.push(sha256(concatBytes(...spentOutputs.map((o) => u64le(o.amount)))));
    parts.push(sha256(concatBytes(...spentOutputs.map((o) => serializeVarBytes(o.scriptPubKey)))));
    parts.push(sha256(concatBytes(...tx.inputs.map((i) => u32le(i.sequence)))));
  }

  const outputMode = hashType & 3;
  if (outputMode !== SIGHASH_NONE && outputMode !== SIGHASH_SINGLE) {
    parts.push(sha256(concatBytes(...tx.outputs.map(serializeTxOutput))));
  }

  // spend_type = 2*ext_flag + annex_present (0x02 for a script path without annex, 0x03 with one)
  parts.push(Uint8Array.of(extFlag * 2 + (annex !== null ? 1 : 0)));

  if (anyoneCanPay) {
    parts.push(serializeOutPoint(input));
    parts.push(u64le(spent.amount));
    parts.push(serializeVarBytes(spent.scriptPubKey));
    parts.push(u32le(input.sequence));
  } else {
    parts.push(u32le(inputIndex));
  }

  if (annex !== null) {
    parts.push(sha256(serializeVarBytes(annex)));
  }

  if (outputMode === SIGHASH_SINGLE) {
    parts.push(sha256(serializeTxOutput(tx.outputs[inputIndex] as (typeof tx.outputs)[number])));
  }

  if (extFlag === 1) {
    parts.push(params.leafHash as Uint8Array);
    parts.push(Uint8Array.of(params.keyVersion ?? TAPSCRIPT_KEY_VERSION));
    parts.push(u32le(params.codeseparatorPosition ?? NO_CODESEPARATOR));
  }

  return concatBytes(...parts);
}

/** TaggedHash("TapSighash", preimage). */
export function taprootSighash(params: TaprootSighashParams): Uint8Array {
  return tapSighash(taprootSigMsg(params));
}

export interface P2mrScriptPathSighashParams
  extends Omit<TaprootSighashParams, 'extFlag' | 'leafHash'> {
  /** TapLeaf hash of the leaf being executed. */
  readonly leafHash: Uint8Array;
}

/**
 * Signature hash for a P2MR script-path spend: ext_flag is fixed at 1.
 *
 * It does one extra thing the generic interface does not: it checks that the spent output really
 * has the `OP_2 <32 bytes>` shape. `PrecomputedTransactionData::Init` in Core v29.0 recognizes
 * taproot inputs by `OP_1`, and in a mixed transaction a P2TR input can let that cache be prepared
 * anyway, masking the fact that the P2MR input was never recognized -- this check stops it up front.
 */
export function p2mrScriptPathSighash(params: P2mrScriptPathSighashParams): Uint8Array {
  // An out-of-range index or a spentOutputs count mismatch is reported more precisely by the
  // generic validation; only the shape is checked here
  const spent = params.spentOutputs[params.inputIndex];
  if (spent !== undefined) {
    assert(
      isP2mrScriptPubKey(spent.scriptPubKey),
      'NOT_A_P2MR_OUTPUT',
      `input ${params.inputIndex} does not spend a P2MR output (expected 34 bytes of OP_2 OP_PUSHBYTES_32 <32 bytes>)`,
    );
  }
  return taprootSighash({ ...params, extFlag: 1 });
}
