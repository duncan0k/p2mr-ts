/**
 * The single error type used across the library.
 *
 * Assert on `code` instead of matching `message`, so callers and tests stay stable.
 */
export type P2mrErrorCode =
  // Construction-interface constraints (wallet/construction layer, not consensus rules)
  | 'INTERNAL_PUBKEY_NOT_SUPPORTED'
  | 'SCRIPT_TREE_REQUIRED'
  | 'SINGLE_LEAF_NOT_ALLOWED'
  | 'LEAF_VERSION_NOT_ALLOWED'
  | 'OP_SUCCESS_NOT_ALLOWED'
  | 'ANNEX_NOT_ALLOWED'
  // Structural errors
  | 'INVALID_HEX'
  | 'INVALID_TREE_NODE'
  | 'INVALID_BRANCH_ARITY'
  | 'INVALID_LEAF_SCRIPT'
  | 'INVALID_LEAF_VERSION'
  | 'TREE_TOO_DEEP'
  // Control block
  | 'INVALID_CONTROL_BLOCK_LENGTH'
  | 'INVALID_CONTROL_BLOCK_PARITY'
  | 'CONTROL_BLOCK_PATH_TOO_LONG'
  // Address / scriptPubKey
  | 'INVALID_MERKLE_ROOT'
  | 'INVALID_SCRIPT_PUBKEY'
  | 'UNKNOWN_NETWORK'
  | 'INVALID_ADDRESS'
  | 'ADDRESS_WRONG_CHECKSUM_VARIANT'
  | 'ADDRESS_WRONG_HRP'
  | 'ADDRESS_WRONG_WITNESS_VERSION'
  | 'ADDRESS_WRONG_PROGRAM_LENGTH'
  // Witness
  | 'INVALID_ANNEX'
  // Transaction / signature hash
  | 'INVALID_HASH_TYPE'
  | 'INVALID_EXT_FLAG'
  | 'INVALID_INPUT_INDEX'
  | 'SPENT_OUTPUTS_MISMATCH'
  | 'MISSING_LEAF_HASH'
  | 'INVALID_LEAF_HASH'
  | 'INVALID_KEY_VERSION'
  | 'INVALID_CODESEPARATOR_POSITION'
  | 'SIGHASH_SINGLE_WITHOUT_OUTPUT'
  | 'NOT_A_P2MR_OUTPUT'
  | 'INVALID_TRANSACTION';

export class P2mrError extends Error {
  readonly code: P2mrErrorCode;

  constructor(code: P2mrErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = 'P2mrError';
    this.code = code;
  }
}

/** Throw a P2mrError carrying `code` when the assertion fails. */
export function assert(
  condition: unknown,
  code: P2mrErrorCode,
  message: string,
): asserts condition {
  if (!condition) throw new P2mrError(code, message);
}
