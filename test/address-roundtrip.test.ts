import { describe, expect, it } from 'vitest';
import {
  addressMatchesMerkleRoot,
  buildP2mrScriptPubKey,
  bytesToHex,
  decodeP2mrAddress,
  encodeP2mrAddress,
  hexToBytes,
  parseControlBlock,
  tapLeafHash,
  verifyControlBlock,
} from '../src/index.js';
import { isErrorVector, loadVectorFile } from './vectors.js';

/**
 * From a differential review of bitcoinjs-lib PR #2312: that review split
 * "derive address / scriptPubKey / merkle root from one another" into its own fixture,
 * so the same entry-point tests are added here.
 */
describe('address <-> scriptPubKey <-> merkle root form a closed triangle', () => {
  const ROOT = hexToBytes('c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b');
  const ADDR = 'bc1zc5jhzjnlf8pg4mdmhfuvqpvnr2quyd9j7mye5uly6psg9twghu4ssr0v9k';

  it('encode produces the mainnet address recorded in the external fixture', () => {
    expect(encodeP2mrAddress(ROOT, 'mainnet')).toBe(ADDR);
  });

  it('addressMatchesMerkleRoot: true for the same root, false for a different one, throws on a network mismatch', () => {
    expect(addressMatchesMerkleRoot(ADDR, ROOT)).toBe(true);
    expect(addressMatchesMerkleRoot(ADDR, ROOT, 'mainnet')).toBe(true);
    const other = Uint8Array.from(ROOT);
    other[0] = (other[0] as number) ^ 0x01;
    expect(addressMatchesMerkleRoot(ADDR, other)).toBe(false);
    expect(() => addressMatchesMerkleRoot(ADDR, ROOT, 'testnet')).toThrowError();
  });

  it('rebuilds the scriptPubKey from the address alone: every positive case in the official vectors that carries an address', () => {
    const vectors = loadVectorFile('p2mr_construction.json').test_vectors.filter(
      (v) => !isErrorVector(v) && typeof v.expected?.bip350Address === 'string',
    );
    expect(vectors.length).toBeGreaterThanOrEqual(6);
    for (const v of vectors) {
      const { merkleRoot } = decodeP2mrAddress(v.expected!.bip350Address as string);
      expect(bytesToHex(buildP2mrScriptPubKey(merkleRoot)), v.id).toBe(v.expected!.scriptPubKey);
    }
  });
});

describe('bogus control blocks over an m=0 tree', () => {
  const leafScript = hexToBytes(
    '20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac',
  );
  // Single-leaf tree: the merkle root is the leaf hash
  const merkleRoot = tapLeafHash(leafScript, 0xc0);

  it('a 33-byte control block has a legal shape (m=1) but must never verify', () => {
    const bogus = Uint8Array.of(0xc1, ...new Array<number>(32).fill(0xaa));
    expect(parseControlBlock(bogus).m).toBe(1);
    expect(verifyControlBlock({ leafScript, controlBlock: bogus, merkleRoot })).toBe(false);
  });

  it('a genuine m=0 control block is 1 byte long and verifies', () => {
    expect(verifyControlBlock({ leafScript, controlBlock: Uint8Array.of(0xc1), merkleRoot })).toBe(
      true,
    );
  });
});
