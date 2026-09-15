/**
 * A minimal tapscript opcode scanner with one job: decide whether a leaf script contains OP_SUCCESSx.
 *
 * It must decode opcode by opcode (skipping push data) rather than scanning raw bytes --
 * the leaf script `20<32 bytes>7f` from the vectors contains bytes such as 0xfa and 0xef inside
 * its 32-byte push payload, and those fall in the OP_SUCCESS range, so a raw scan yields false
 * positives.
 */

/** OP_SUCCESSx opcode ranges defined by BIP-342 (inclusive). */
const OP_SUCCESS_RANGES: ReadonlyArray<readonly [number, number]> = [
  [80, 80], // 0x50
  [98, 98], // 0x62
  [126, 129], // 0x7e-0x81
  [131, 134], // 0x83-0x86
  [137, 138], // 0x89-0x8a
  [141, 142], // 0x8d-0x8e
  [149, 153], // 0x95-0x99
  [187, 254], // 0xbb-0xfe
];

/** Report whether an opcode is OP_SUCCESSx. */
export function isOpSuccess(opcode: number): boolean {
  return OP_SUCCESS_RANGES.some(([lo, hi]) => opcode >= lo && opcode <= hi);
}

export interface OpSuccessHit {
  /** Numeric value of the opcode. */
  readonly opcode: number;
  /** Byte offset of that opcode within the script. */
  readonly offset: number;
}

export interface ScriptScanResult {
  /** The first OP_SUCCESSx encountered, or null if there is none. */
  readonly opSuccess: OpSuccessHit | null;
  /**
   * Decoding ran off the end of the script before any OP_SUCCESSx (a push length exceeded the
   * remaining bytes).
   *
   * Such a script can never execute successfully and no later byte can trigger OP_SUCCESS,
   * so it is treated as "no OP_SUCCESS found", though the condition is still reported to the caller.
   */
  readonly truncated: boolean;
}

/**
 * Scan a leaf script and return its first OP_SUCCESSx.
 *
 * Returns immediately on OP_SUCCESSx, matching BIP-342: success even if later bytes fail to decode.
 */
export function scanLeafScript(script: Uint8Array): ScriptScanResult {
  let i = 0;
  while (i < script.length) {
    const opcode = script[i] as number;
    i += 1;
    if (isOpSuccess(opcode)) {
      return { opSuccess: { opcode, offset: i - 1 }, truncated: false };
    }

    let dataLen = 0;
    if (opcode >= 0x01 && opcode <= 0x4b) {
      dataLen = opcode;
    } else if (opcode === 0x4c || opcode === 0x4d || opcode === 0x4e) {
      const sizeLen = opcode === 0x4c ? 1 : opcode === 0x4d ? 2 : 4;
      if (i + sizeLen > script.length) return { opSuccess: null, truncated: true };
      let n = 0;
      for (let k = 0; k < sizeLen; k++) n += (script[i + k] as number) * 2 ** (8 * k);
      i += sizeLen;
      dataLen = n;
    }

    if (i + dataLen > script.length) return { opSuccess: null, truncated: true };
    i += dataLen;
  }
  return { opSuccess: null, truncated: false };
}
