import { describe, expect, it } from 'vitest';
import { isOpSuccess, scanLeafScript } from '../src/index.js';

/**
 * OP_SUCCESSx as listed in the BIP-342 text: 80, 98, 126-129, 131-134, 137-138, 141-142, 149-153, 187-254.
 * Enumerated here one by one from that text (without reusing the range table in src/script.ts), 87 in total.
 */
const OP_SUCCESS_FROM_BIP342: readonly number[] = [
  80,
  98,
  126, 127, 128, 129,
  131, 132, 133, 134,
  137, 138,
  141, 142,
  149, 150, 151, 152, 153,
  ...Array.from({ length: 254 - 187 + 1 }, (_, i) => 187 + i),
];
const SUCCESS_SET = new Set(OP_SUCCESS_FROM_BIP342);

describe('the full OP_SUCCESSx table', () => {
  it('BIP-342 defines 87 OP_SUCCESSx opcodes', () => {
    expect(OP_SUCCESS_FROM_BIP342).toHaveLength(87);
  });

  it('isOpSuccess agrees with the BIP-342 text for every opcode in 0..255', () => {
    for (let op = 0; op <= 255; op++) {
      expect(isOpSuccess(op), `opcode ${op}`).toBe(SUCCESS_SET.has(op));
    }
  });

  it('single-byte script: an OP_SUCCESSx hits at offset 0, anything else does not hit', () => {
    for (let op = 0; op <= 255; op++) {
      const { opSuccess } = scanLeafScript(Uint8Array.of(op));
      if (SUCCESS_SET.has(op)) {
        expect(opSuccess, `opcode ${op}`).toEqual({ opcode: op, offset: 0 });
      } else {
        expect(opSuccess, `opcode ${op}`).toBeNull();
      }
    }
  });

  it('a byte of the same value inside push data is not an OP_SUCCESSx (direct push and PUSHDATA1/2/4, one pass each)', () => {
    for (const op of OP_SUCCESS_FROM_BIP342) {
      const wrapped = [
        Uint8Array.of(0x01, op),
        Uint8Array.of(0x4c, 0x01, op),
        Uint8Array.of(0x4d, 0x01, 0x00, op),
        Uint8Array.of(0x4e, 0x01, 0x00, 0x00, 0x00, op),
      ];
      for (const script of wrapped) {
        expect(scanLeafScript(script), `opcode ${op}`).toEqual({ opSuccess: null, truncated: false });
      }
      // Once the push has ended, the same byte is an opcode again
      expect(scanLeafScript(Uint8Array.of(0x01, op, op)).opSuccess).toEqual({ opcode: op, offset: 2 });
    }
  });

  it('a push length running past the end: treated as no hit and flagged truncated', () => {
    expect(scanLeafScript(Uint8Array.of(0x02, 0x50))).toEqual({ opSuccess: null, truncated: true });
    expect(scanLeafScript(Uint8Array.of(0x4c))).toEqual({ opSuccess: null, truncated: true });
    expect(scanLeafScript(Uint8Array.of(0x4d, 0xff, 0xff, 0x00))).toEqual({
      opSuccess: null,
      truncated: true,
    });
  });

  it('returns as soon as an OP_SUCCESSx is hit and stops decoding the bytes that follow', () => {
    expect(scanLeafScript(Uint8Array.of(0x50, 0x62)).opSuccess).toEqual({ opcode: 0x50, offset: 0 });
    // An undecodable push following the OP_SUCCESS does not matter
    expect(scanLeafScript(Uint8Array.of(0x51, 0x62, 0x4e))).toEqual({
      opSuccess: { opcode: 0x62, offset: 1 },
      truncated: false,
    });
  });

  it('PQC vector shape `20<32 bytes>7f`: the hit is the trailing OP_SUCCESS127, not the 0xfa inside the push data', () => {
    const script = Uint8Array.of(0x20, ...new Array<number>(32).fill(0xfa), 0x7f);
    expect(scanLeafScript(script).opSuccess).toEqual({ opcode: 127, offset: 33 });
  });
});
