import { sha256 } from '@noble/hashes/sha2.js';
import { compactSize, concatBytes, serializeVarBytes, u32le, u64le } from './bytes.js';
import { assert, P2mrError } from './errors.js';

const EMPTY = new Uint8Array(0);

/**
 * A transaction input.
 *
 * `txid` is stored in the **internal byte order of transaction serialization**, i.e. the reverse of
 * the txid a block explorer displays. Run `reverseBytes` first when building from an explorer txid.
 */
export interface TxInput {
  readonly txid: Uint8Array;
  readonly vout: number;
  readonly sequence: number;
  /** scriptSig of a non-segwit input; always empty for a P2MR input. */
  readonly scriptSig?: Uint8Array;
  /**
   * Witness stack of this input.
   *
   * `undefined` in a non-segwit transaction; in a segwit transaction every input has an entry, and
   * an input with no witness is an empty array (BIP-144 requires a witness record for **every**
   * input of a marked transaction).
   */
  readonly witness?: readonly Uint8Array[];
}

export interface TxOutput {
  readonly amount: bigint;
  readonly scriptPubKey: Uint8Array;
}

/** The output being spent (the sighash needs its amount and scriptPubKey). */
export interface SpentOutput {
  readonly amount: bigint;
  readonly scriptPubKey: Uint8Array;
}

export interface Transaction {
  readonly version: number;
  readonly locktime: number;
  readonly inputs: readonly TxInput[];
  readonly outputs: readonly TxOutput[];
}

/** Largest value an 8-byte amount field can hold. */
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn;

/**
 * Throw unless `amount` fits the 8-byte amount field: a bigint (or, for JavaScript callers, a safe
 * integer) in 0..2^64-1. Serialization would otherwise write it modulo 2^64, so -1n would become
 * 0xffffffffffffffff.
 */
export function assertAmount(amount: unknown, what = 'amount'): void {
  const ok =
    typeof amount === 'bigint'
      ? amount >= 0n && amount <= MAX_UINT64
      : typeof amount === 'number' && Number.isSafeInteger(amount) && amount >= 0;
  assert(ok, 'INVALID_TRANSACTION', `${what} must be an integer in 0..2^64-1, got ${String(amount)}`);
}

/** 36-byte outpoint: 32-byte txid (internal order) + 4-byte LE vout. */
export function serializeOutPoint(input: TxInput): Uint8Array {
  assert(
    input.txid.length === 32,
    'INVALID_TRANSACTION',
    `txid must be 32 bytes, got ${input.txid.length}`,
  );
  assert(isUint32(input.vout), 'INVALID_TRANSACTION', `vout must be a uint32, got ${String(input.vout)}`);
  return concatBytes(input.txid, u32le(input.vout));
}

/** 8-byte LE amount + compact_size-prefixed scriptPubKey. */
export function serializeTxOutput(output: TxOutput): Uint8Array {
  assertAmount(output.amount, 'output amount');
  return concatBytes(u64le(BigInt(output.amount)), serializeVarBytes(output.scriptPubKey));
}

class Reader {
  private offset = 0;

  constructor(private readonly data: Uint8Array) {}

  get consumed(): number {
    return this.offset;
  }

  get remaining(): number {
    return this.data.length - this.offset;
  }

  take(n: number): Uint8Array {
    if (this.offset + n > this.data.length) {
      throw new P2mrError('INVALID_TRANSACTION', 'transaction data ran out mid-parse');
    }
    const out = this.data.slice(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  u8(): number {
    return this.take(1)[0] as number;
  }

  u32(): number {
    const b = this.take(4);
    return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(0, true);
  }

  u64(): bigint {
    const b = this.take(8);
    return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(0, true);
  }

  /**
   * Read a CompactSize, rejecting non-canonical encodings as Bitcoin Core's ReadCompactSize does
   * ("non-canonical ReadCompactSize()"): a value must use the shortest form, so that decoding and
   * encoding stay mutually inverse.
   */
  compactSize(): number {
    const first = this.u8();
    if (first < 0xfd) return first;
    let v: bigint;
    let min: bigint;
    if (first === 0xfd) {
      const b = this.take(2);
      v = BigInt(new DataView(b.buffer, b.byteOffset, b.byteLength).getUint16(0, true));
      min = 0xfdn;
    } else if (first === 0xfe) {
      v = BigInt(this.u32());
      min = 0x1_0000n;
    } else {
      v = this.u64();
      min = 0x1_0000_0000n;
    }
    if (v < min) {
      throw new P2mrError(
        'INVALID_TRANSACTION',
        `non-canonical compactSize: ${v} encoded with prefix 0x${first.toString(16)}`,
      );
    }
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new P2mrError('INVALID_TRANSACTION', 'compactSize exceeds the safe integer range');
    }
    return Number(v);
  }

  varBytes(): Uint8Array {
    return this.take(this.compactSize());
  }
}

/**
 * Decode a transaction (segwit and non-segwit alike).
 *
 * The witness stacks of a segwit transaction are kept on `TxInput.witness`, so `decodeTransaction`
 * and `encodeTransaction` are mutually inverse and round-trip byte-for-byte.
 */
export function decodeTransaction(raw: Uint8Array): Transaction {
  const r = new Reader(raw);
  const version = r.u32();

  let inputCount = r.compactSize();
  let hasWitness = false;
  if (inputCount === 0) {
    const flag = r.u8();
    assert(flag === 0x01, 'INVALID_TRANSACTION', `unknown segwit flag 0x${flag.toString(16)}`);
    hasWitness = true;
    inputCount = r.compactSize();
  }

  const inputs: TxInput[] = [];
  for (let i = 0; i < inputCount; i++) {
    const txid = r.take(32);
    const vout = r.u32();
    const scriptSig = r.varBytes();
    const sequence = r.u32();
    inputs.push({ txid, vout, sequence, scriptSig });
  }

  const outputCount = r.compactSize();
  const outputs: TxOutput[] = [];
  for (let i = 0; i < outputCount; i++) {
    const amount = r.u64();
    const scriptPubKey = r.varBytes();
    outputs.push({ amount, scriptPubKey });
  }

  let withWitness: TxInput[] | null = null;
  if (hasWitness) {
    const stacks: Uint8Array[][] = [];
    for (let i = 0; i < inputCount; i++) {
      const items = r.compactSize();
      const stack: Uint8Array[] = [];
      for (let k = 0; k < items; k++) stack.push(r.varBytes());
      stacks.push(stack);
    }
    // Matching UnserializeTransaction in Core: a segwit marker with no witness at all is invalid
    assert(
      stacks.some((s) => s.length > 0),
      'INVALID_TRANSACTION',
      'segwit marker present but every input witness is empty (the Core parser reports "Superfluous witness record")',
    );
    withWitness = inputs.map((input, i) => ({ ...input, witness: stacks[i] as Uint8Array[] }));
  }

  const locktime = r.u32();
  assert(r.remaining === 0, 'INVALID_TRANSACTION', `transaction has ${r.remaining} trailing bytes`);

  return { version, locktime, inputs: withWitness ?? inputs, outputs };
}

export interface EncodeTransactionOptions {
  /**
   * Whether to write the BIP-144 segwit marker/flag and the witness stacks.
   *
   * The default follows the transaction itself: `true` if any input carries a non-empty witness,
   * `false` otherwise. That makes `encodeTransaction(decodeTransaction(raw))` byte-for-byte `raw`.
   *
   * An explicit `false` yields the txid preimage. An explicit `true` with no non-empty witness is
   * an error -- the BIP-144 marker requires at least one non-empty witness, otherwise Core rejects
   * the parse with "Superfluous witness record".
   */
  readonly witness?: boolean;
}

/** Transaction serialization, the inverse of `decodeTransaction`. */
export function encodeTransaction(
  tx: Transaction,
  options: EncodeTransactionOptions = {},
): Uint8Array {
  const anyWitness = tx.inputs.some((i) => i.witness !== undefined && i.witness.length > 0);
  const includeWitness = options.witness ?? anyWitness;
  assert(
    !includeWitness || anyWitness,
    'INVALID_TRANSACTION',
    'witness: true but no input carries a non-empty witness; the BIP-144 segwit marker requires at least one non-empty witness',
  );

  assertTransactionFields(tx);
  const parts: Uint8Array[] = [u32le(tx.version)];
  if (includeWitness) parts.push(Uint8Array.of(0x00, 0x01));

  parts.push(compactSize(tx.inputs.length));
  for (const input of tx.inputs) {
    parts.push(serializeOutPoint(input));
    parts.push(serializeVarBytes(input.scriptSig ?? EMPTY));
    parts.push(u32le(input.sequence));
  }

  parts.push(compactSize(tx.outputs.length));
  for (const output of tx.outputs) parts.push(serializeTxOutput(output));

  if (includeWitness) {
    for (const input of tx.inputs) {
      const stack = input.witness ?? [];
      parts.push(compactSize(stack.length));
      for (const item of stack) parts.push(serializeVarBytes(item));
    }
  }

  parts.push(u32le(tx.locktime));
  return concatBytes(...parts);
}

function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/**
 * txid = double-SHA256(serialization **without** the witness).
 *
 * Returned in **internal transaction byte order**, the same convention as `TxInput.txid`, ready to
 * be used directly when building the input of a following transaction. Block explorers and RPC
 * display the reversed hex: `bytesToHex(reverseBytes(computeTxid(tx)))`.
 */
export function computeTxid(tx: Transaction): Uint8Array {
  return hash256(encodeTransaction(tx, { witness: false }));
}

/**
 * wtxid = double-SHA256(serialization **with** the witness).
 *
 * A non-segwit transaction has no witness records, so its serialization equals the txid preimage
 * and the wtxid therefore equals the txid (BIP-141). Byte order is the same as `computeTxid`.
 */
export function computeWtxid(tx: Transaction): Uint8Array {
  return hash256(encodeTransaction(tx));
}

/** nSequence of an input that is final; when every input has it, nLockTime is not enforced. */
export const SEQUENCE_FINAL = 0xffffffff;

/** nLockTime values from this one on are timestamps rather than block heights. */
export const LOCKTIME_THRESHOLD = 500_000_000;

/** Whether a value is what a 4-byte unsigned field can hold, so that serializing it keeps its value. */
export function isUint32(n: number): boolean {
  return Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
}

/**
 * Throw unless the lock time and every nSequence are uint32 values. Serialization writes any number
 * modulo 2^32, so a sequence of -1 would be written as SEQUENCE_FINAL while looking otherwise.
 */
export function assertLockFieldsUint32(tx: Transaction): void {
  assert(isUint32(tx.locktime), 'INVALID_TRANSACTION', `nLockTime must be a uint32, got ${String(tx.locktime)}`);
  for (const [i, input] of tx.inputs.entries()) {
    assert(
      isUint32(input.sequence),
      'INVALID_TRANSACTION',
      `nSequence of input ${i} must be a uint32, got ${String(input.sequence)}`,
    );
  }
}

/**
 * Throw unless every fixed-width numeric field of the transaction holds its value exactly: version,
 * lock time, every vout and nSequence (uint32), and every output amount (uint64). Used by
 * serialization and by the signature hash, which would otherwise reduce values modulo 2^32 / 2^64.
 */
export function assertTransactionFields(tx: Transaction): void {
  assert(isUint32(tx.version), 'INVALID_TRANSACTION', `version must be a uint32, got ${String(tx.version)}`);
  assertLockFieldsUint32(tx);
  for (const [i, input] of tx.inputs.entries()) {
    assert(
      isUint32(input.vout),
      'INVALID_TRANSACTION',
      `vout of input ${i} must be a uint32, got ${String(input.vout)}`,
    );
  }
  for (const [i, output] of tx.outputs.entries()) assertAmount(output.amount, `amount of output ${i}`);
}

/**
 * Whether a transaction may be included in a block at `blockHeight`, by the rule of Core's
 * `IsFinalTx` for a lock time that is a block height: the lock time is zero, or below the block's
 * height, or every input has SEQUENCE_FINAL. A lock time that is a timestamp is refused, since that
 * rule compares it with a block time instead.
 */
export function isFinalAtHeight(tx: Transaction, blockHeight: number): boolean {
  assert(
    Number.isSafeInteger(blockHeight) && blockHeight >= 0,
    'INVALID_TRANSACTION',
    `block height must be a non-negative integer, got ${String(blockHeight)}`,
  );
  assertLockFieldsUint32(tx);
  assert(
    tx.locktime < LOCKTIME_THRESHOLD,
    'INVALID_LOCKTIME',
    `lock time ${tx.locktime} is a timestamp; only lock times below ${LOCKTIME_THRESHOLD} are block heights`,
  );
  if (tx.locktime === 0 || tx.locktime < blockHeight) return true;
  return tx.inputs.every((input) => input.sequence === SEQUENCE_FINAL);
}

/** compact_size encoding re-exported for external use (the sighash needs a length-prefixed scriptPubKey). */
export { compactSize, serializeVarBytes };
