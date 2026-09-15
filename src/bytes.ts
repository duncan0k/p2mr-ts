import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import { P2mrError } from './errors.js';

export { bytesToHex, concatBytes, hexToBytes };

/** Normalize a hex string or byte array to a Uint8Array (a fresh copy, so later mutations of the
 * caller's array cannot leak in). */
export function toBytes(value: Uint8Array | string, what = 'value'): Uint8Array {
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (typeof value !== 'string') {
    throw new P2mrError('INVALID_HEX', `${what} must be a hex string or a Uint8Array`);
  }
  if (value.length % 2 !== 0 || (value.length > 0 && !/^[0-9a-fA-F]+$/.test(value))) {
    throw new P2mrError('INVALID_HEX', `${what} is not a valid hex string`);
  }
  return hexToBytes(value.toLowerCase());
}

/** Lexicographic comparison (used by BIP-341 TapBranch). */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i] as number;
    const y = b[i] as number;
    if (x !== y) return x < y ? -1 : 1;
  }
  return a.length - b.length;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && compareBytes(a, b) === 0;
}

/** Bitcoin CompactSize (varint) encoding. */
export function compactSize(n: number | bigint): Uint8Array {
  const v = BigInt(n);
  if (v < 0n || v > 0xffff_ffff_ffff_ffffn) {
    throw new P2mrError('INVALID_TRANSACTION', 'compactSize out of range');
  }
  if (v < 0xfdn) return Uint8Array.of(Number(v));
  if (v <= 0xffffn) return concatBytes(Uint8Array.of(0xfd), u16le(Number(v)));
  if (v <= 0xffff_ffffn) return concatBytes(Uint8Array.of(0xfe), u32le(Number(v)));
  return concatBytes(Uint8Array.of(0xff), u64le(v));
}

/** compact_size(len(data)) || data */
export function serializeVarBytes(data: Uint8Array): Uint8Array {
  return concatBytes(compactSize(data.length), data);
}

export function u16le(n: number): Uint8Array {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
}

export function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

export function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

/** Reverse byte order (block explorer txid <-> internal transaction byte order). */
export function reverseBytes(b: Uint8Array): Uint8Array {
  return Uint8Array.from(b).reverse();
}
