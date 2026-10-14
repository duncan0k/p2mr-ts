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
 * BIP-342 keeps the 520-byte limit on stack elements, both for push opcodes and for the initial
 * stack (MAX_SCRIPT_ELEMENT_SIZE in Bitcoin Core).
 */
export const MAX_SCRIPT_ELEMENT_SIZE = 520;

/** OP_16, the highest opcode that only pushes a constant (0x00-0x60 are all push opcodes). */
const OP_16 = 0x60;

export interface OversizedPush {
  /** Byte offset of the push opcode within the script. */
  readonly offset: number;
  /** Number of bytes the opcode pushes. */
  readonly size: number;
}

export interface LeafScriptAnalysis extends ScriptScanResult {
  /**
   * The first push of more than MAX_SCRIPT_ELEMENT_SIZE bytes before any OP_SUCCESSx, or null.
   *
   * Bitcoin Core's EvalScript checks the push size before it looks at fExec, so such a push fails
   * the script even inside an unexecuted OP_IF branch: the leaf can never be spent.
   */
  readonly oversizedPush: OversizedPush | null;
  /**
   * Every opcode is a push opcode (0x00-0x60). Such a leaf leaves only constants on the stack: it
   * is either anyone-can-spend (a true top element) or never spendable. Always false when the
   * script is truncated or contains OP_SUCCESSx.
   */
  readonly pushOnly: boolean;
}

/**
 * Decode a leaf script opcode by opcode and report everything the construction interface checks:
 * the first OP_SUCCESSx, truncation, oversized pushes, and whether it is push-only.
 *
 * Mirrors the order of BIP-342: the OP_SUCCESSx pre-scan stops at the first OP_SUCCESSx (later
 * bytes do not matter), and a decoding failure before that point fails the script.
 */
export function analyzeLeafScript(script: Uint8Array): LeafScriptAnalysis {
  let oversizedPush: OversizedPush | null = null;
  let pushOnly = true;
  let i = 0;
  while (i < script.length) {
    const offset = i;
    const opcode = script[i] as number;
    i += 1;
    if (isOpSuccess(opcode)) {
      return { opSuccess: { opcode, offset }, truncated: false, oversizedPush, pushOnly: false };
    }
    if (opcode > OP_16) pushOnly = false;

    let dataLen = 0;
    if (opcode >= 0x01 && opcode <= 0x4b) {
      dataLen = opcode;
    } else if (opcode === 0x4c || opcode === 0x4d || opcode === 0x4e) {
      const sizeLen = opcode === 0x4c ? 1 : opcode === 0x4d ? 2 : 4;
      if (i + sizeLen > script.length) {
        return { opSuccess: null, truncated: true, oversizedPush, pushOnly: false };
      }
      let n = 0;
      for (let k = 0; k < sizeLen; k++) n += (script[i + k] as number) * 2 ** (8 * k);
      i += sizeLen;
      dataLen = n;
    }

    if (i + dataLen > script.length) {
      return { opSuccess: null, truncated: true, oversizedPush, pushOnly: false };
    }
    if (dataLen > MAX_SCRIPT_ELEMENT_SIZE && oversizedPush === null) {
      oversizedPush = { offset, size: dataLen };
    }
    i += dataLen;
  }
  return { opSuccess: null, truncated: false, oversizedPush, pushOnly };
}

/**
 * Scan a leaf script and return its first OP_SUCCESSx.
 *
 * Returns immediately on OP_SUCCESSx, matching BIP-342: success even if later bytes fail to decode.
 */
export function scanLeafScript(script: Uint8Array): ScriptScanResult {
  const { opSuccess, truncated } = analyzeLeafScript(script);
  return { opSuccess, truncated };
}
