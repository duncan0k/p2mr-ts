import { assert, P2mrError } from './errors.js';
import type { ParsedControlBlock } from './controlBlock.js';
import { parseControlBlock } from './controlBlock.js';

/** Marker byte that starts an annex. */
export const ANNEX_PREFIX = 0x50;

export interface AssembleScriptPathWitnessOptions {
  /**
   * Input stack items for the leaf script, in the order the script expects (the item pushed first
   * comes first).
   */
  readonly stack?: readonly Uint8Array[];
  readonly leafScript: Uint8Array;
  readonly controlBlock: Uint8Array;
  /** Optional annex, which must start with 0x50; rejected by default, allowAnnex must be set explicitly. */
  readonly annex?: Uint8Array;
  /**
   * Allow carrying an annex. Defaults to false.
   *
   * Consensus permits an annex, but the taproot **policy** of Bitcoin Core v29.0 rejects
   * transactions carrying one, so a spend assembled that way will not enter the mempool of
   * mainstream nodes. The wallet layer emits no annex by default; low-level tooling opts in
   * explicitly when building test cases.
   */
  readonly allowAnnex?: boolean;
}

/**
 * Assemble the witness stack of a script-path spend: [stack items..., leaf script, control block, (annex)].
 *
 * An annex is covered by the signature and counted towards weight only at the consensus layer,
 * where it is otherwise ignored during validation; the taproot **policy** of Bitcoin Core v29.0
 * rejects transactions carrying one -- consensus-valid does not mean mempool-accepted.
 */
export function assembleScriptPathWitness(
  options: AssembleScriptPathWitnessOptions,
): Uint8Array[] {
  // Parse once up front, so a malformed control block is caught before assembly
  parseControlBlock(options.controlBlock);
  assert(
    options.leafScript.length > 0,
    'INVALID_LEAF_SCRIPT',
    'leaf script must not be empty',
  );

  const witness: Uint8Array[] = [
    ...(options.stack ?? []),
    options.leafScript,
    options.controlBlock,
  ];

  if (options.annex !== undefined) {
    assert(
      options.allowAnnex === true,
      'ANNEX_NOT_ALLOWED',
      'an annex is rejected by default: the taproot policy of Bitcoin Core v29.0 does not accept transactions carrying one. Pass allowAnnex: true explicitly if you really need to assemble one',
    );
    assert(
      options.annex.length > 0 && options.annex[0] === ANNEX_PREFIX,
      'INVALID_ANNEX',
      'annex must be non-empty and start with 0x50',
    );
    witness.push(options.annex);
  }

  return witness;
}

export type WitnessShapeErrorCode =
  | 'WITNESS_TOO_FEW_ELEMENTS'
  | 'WITNESS_ANNEX_WITHOUT_SCRIPT_PATH'
  | 'WITNESS_CONTROL_BLOCK_INVALID';

export interface WitnessShapeOk {
  readonly valid: true;
  readonly hasAnnex: boolean;
  readonly annex: Uint8Array | null;
  readonly controlBlock: Uint8Array;
  readonly parsedControlBlock: ParsedControlBlock;
  readonly leafScript: Uint8Array;
  readonly stack: readonly Uint8Array[];
}

export interface WitnessShapeError {
  readonly valid: false;
  readonly code: WitnessShapeErrorCode;
  readonly reason: string;
  readonly hasAnnex: boolean;
}

export type WitnessShapeResult = WitnessShapeOk | WitnessShapeError;

/**
 * Validate the shape of a P2MR witness stack.
 *
 * Two negative cases specific to P2MR that the upstream construction vectors do not cover at all:
 *   1. fewer than 2 elements -> failure;
 *   2. exactly 2 elements whose last element starts with 0x50 -> failure.
 *      Stripping the annex leaves 1 element, which is a key path under P2TR, and P2MR has no key path.
 */
export function validateWitnessShape(
  witness: readonly Uint8Array[],
): WitnessShapeResult {
  if (witness.length < 2) {
    return {
      valid: false,
      code: 'WITNESS_TOO_FEW_ELEMENTS',
      reason: `a P2MR witness stack needs at least 2 elements (leaf script + control block), got ${witness.length}`,
      hasAnnex: false,
    };
  }

  const last = witness[witness.length - 1] as Uint8Array;
  const hasAnnex = last.length > 0 && last[0] === ANNEX_PREFIX;
  const elements = hasAnnex ? witness.slice(0, -1) : witness.slice();

  if (elements.length < 2) {
    return {
      valid: false,
      code: 'WITNESS_ANNEX_WITHOUT_SCRIPT_PATH',
      reason:
        'stripping the annex leaves only 1 element. Under P2TR that is a key path spend, and P2MR has no key path, so this fails',
      hasAnnex: true,
    };
  }

  const controlBlock = elements[elements.length - 1] as Uint8Array;
  const leafScript = elements[elements.length - 2] as Uint8Array;
  let parsedControlBlock: ParsedControlBlock;
  try {
    parsedControlBlock = parseControlBlock(controlBlock);
  } catch (err) {
    return {
      valid: false,
      code: 'WITNESS_CONTROL_BLOCK_INVALID',
      reason: err instanceof P2mrError ? err.message : String(err),
      hasAnnex,
    };
  }

  return {
    valid: true,
    hasAnnex,
    annex: hasAnnex ? last : null,
    controlBlock,
    parsedControlBlock,
    leafScript,
    stack: elements.slice(0, -2),
  };
}
