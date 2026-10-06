/**
 * p2mr -- an offline construction library for BIP-360 Pay-to-Merkle-Root.
 *
 * Construction and signature hashing only: tree hashes, control blocks, bech32m witness v2
 * addresses, witness stack assembly, BIP-341/342 signature hashes. No network validation, no signing.
 *
 * BIP-360 is still a Draft and may change at any time; this library tracks the vectors at the
 * pinned commit 620871a7a442e276a058b487cd8743775fb499a4 (BIP-360 v0.12.1).
 */

export { P2mrError } from './errors.js';
export type { P2mrErrorCode } from './errors.js';

export {
  bytesEqual,
  bytesToHex,
  compactSize,
  compareBytes,
  concatBytes,
  hexToBytes,
  reverseBytes,
  serializeVarBytes,
  toBytes,
} from './bytes.js';

export { tapBranchHash, tapLeafHash, tapSighash, taggedHash } from './tagged.js';

export { isOpSuccess, scanLeafScript } from './script.js';
export type { OpSuccessHit, ScriptScanResult } from './script.js';

export {
  analyzeScriptTree,
  collectLeafHashes,
  computeMerkleRoot,
  countLeafPositions,
  DEFAULT_LEAF_VERSION,
  MAX_MERKLE_PATH_LENGTH,
  normalizeScriptTree,
  TRIPWIRED_LEAF_VERSION,
} from './tree.js';
export type {
  LeafEntry,
  NormalizeTreeOptions,
  ScriptLeaf,
  ScriptLeafInput,
  ScriptTreeInput,
  ScriptTreeNode,
} from './tree.js';

export {
  computeMerkleRootFromControlBlock,
  CONTROL_BLOCK_BASE_SIZE,
  encodeControlBlock,
  MAX_CONTROL_BLOCK_SIZE,
  parseControlBlock,
  verifyControlBlock,
} from './controlBlock.js';
export type { ParsedControlBlock } from './controlBlock.js';

export {
  decodeP2mrAddress,
  encodeP2mrAddress,
  NETWORK_HRP,
  P2MR_WITNESS_VERSION,
} from './address.js';
export type { DecodedP2mrAddress, DecodeP2mrAddressOptions, Network } from './address.js';

export {
  addressMatchesMerkleRoot,
  buildP2mrScriptPubKey,
  createP2mrOutput,
  isP2mrScriptPubKey,
  parseP2mrScriptPubKey,
} from './output.js';
export type {
  CreateP2mrOutputOptions,
  P2mrLeafOutput,
  P2mrOutput,
} from './output.js';

export {
  ANNEX_PREFIX,
  assembleScriptPathWitness,
  validateWitnessShape,
} from './witness.js';
export type {
  AssembleScriptPathWitnessOptions,
  WitnessShapeError,
  WitnessShapeErrorCode,
  WitnessShapeOk,
  WitnessShapeResult,
} from './witness.js';

export {
  computeTxid,
  computeWtxid,
  decodeTransaction,
  encodeTransaction,
  isFinalAtHeight,
  LOCKTIME_THRESHOLD,
  SEQUENCE_FINAL,
  serializeOutPoint,
  serializeTxOutput,
} from './tx.js';
export type {
  EncodeTransactionOptions,
  SpentOutput,
  Transaction,
  TxInput,
  TxOutput,
} from './tx.js';

export {
  NO_CODESEPARATOR,
  p2mrScriptPathSighash,
  SIGHASH_ALL,
  SIGHASH_ANYONECANPAY,
  SIGHASH_DEFAULT,
  SIGHASH_NONE,
  SIGHASH_SINGLE,
  TAPSCRIPT_KEY_VERSION,
  taprootSighash,
  taprootSigMsg,
} from './sighash.js';
export type { P2mrScriptPathSighashParams, TaprootSighashParams } from './sighash.js';

export {
  assembleMldsa44Witness,
  assertMldsa44AddressesAllowed,
  buildMldsa44LeafScript,
  createMldsa44Output,
  MLDSA44_ACTIVATION_MARGIN,
  MLDSA44_CONTEXT,
  MLDSA44_FAIL_LEAF_SCRIPT,
  MLDSA44_KEY_VERSION,
  MLDSA44_PUBLIC_KEY_CHUNK_SIZES,
  MLDSA44_PUBLIC_KEY_SIZE,
  MLDSA44_SECRET_KEY_SIZE,
  MLDSA44_SEED_SIZE,
  MLDSA44_SIGNATURE_CHUNK_SIZES,
  MLDSA44_SIGNATURE_SIZE,
  mldsa44ActivationHeight,
  mldsa44AddressesAllowed,
  mldsa44Keygen,
  mldsa44MerkleRoot,
  mldsa44OutputMatches,
  mldsa44ProtectionStatus,
  mldsa44Sighash,
  mldsa44Sign,
  mldsa44Verify,
  OP_CHECKMLDSA44,
  parseMldsa44LeafScript,
  signMldsa44Input,
  splitMldsa44Signature,
  withMldsa44FundingLockTime,
} from './mldsa44.js';
export type {
  AssembleMldsa44WitnessOptions,
  CreateMldsa44OutputOptions,
  Mldsa44ChainState,
  Mldsa44KeyPair,
  Mldsa44Network,
  Mldsa44Output,
  Mldsa44OutputMatchParams,
  Mldsa44ProtectionParams,
  Mldsa44ProtectionStatus,
  Mldsa44SighashParams,
  Mldsa44SignOptions,
  Mldsa44Template,
  ParsedMldsa44Leaf,
  SignMldsa44InputParams,
} from './mldsa44.js';
