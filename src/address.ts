import { bech32, bech32m } from 'bech32';
import { assert, P2mrError } from './errors.js';

/** The witness version for P2MR is fixed at 2. */
export const P2MR_WITNESS_VERSION = 2;

export type Network = 'mainnet' | 'testnet' | 'signet' | 'regtest';

/** Note that testnet and signet share the hrp `tb`; the address alone cannot tell them apart. */
export const NETWORK_HRP: Readonly<Record<Network, string>> = {
  mainnet: 'bc',
  testnet: 'tb',
  signet: 'tb',
  regtest: 'bcrt',
};

const HRP_NETWORKS: Readonly<Record<string, readonly Network[]>> = {
  bc: ['mainnet'],
  tb: ['testnet', 'signet'],
  bcrt: ['regtest'],
};

/** Upper bound on the length covered by the bech32/bech32m checksum; 90 per BIP-173. */
const BECH32_LIMIT = 90;

function hrpFor(network: Network): string {
  const hrp = NETWORK_HRP[network];
  assert(hrp !== undefined, 'UNKNOWN_NETWORK', `unknown network ${String(network)}`);
  return hrp;
}

/**
 * Encode a witness v2 address per BIP-350.
 *
 * Witness versions >= 1 always use bech32m, so mainnet P2MR addresses start with `bc1z` (z encodes v2).
 */
export function encodeP2mrAddress(merkleRoot: Uint8Array, network: Network): string {
  assert(
    merkleRoot.length === 32,
    'INVALID_MERKLE_ROOT',
    `merkle root must be 32 bytes, got ${merkleRoot.length}`,
  );
  const words = [P2MR_WITNESS_VERSION, ...bech32m.toWords(merkleRoot)];
  return bech32m.encode(hrpFor(network), words, BECH32_LIMIT);
}

export interface DecodedP2mrAddress {
  readonly hrp: string;
  /** Networks matching this hrp; `tb` maps to both testnet and signet. */
  readonly networks: readonly Network[];
  readonly witnessVersion: number;
  readonly merkleRoot: Uint8Array;
}

export interface DecodeP2mrAddressOptions {
  /** When set, the hrp is checked against this network. */
  readonly network?: Network;
}

/**
 * Decode and validate a witness v2 P2MR address.
 *
 * The "bech32 instead of bech32m" case is called out explicitly: a v2 address carrying a
 * bech32 checksum is invalid, but an error saying only "bad checksum" hides the real cause.
 */
export function decodeP2mrAddress(
  address: string,
  options: DecodeP2mrAddressOptions = {},
): DecodedP2mrAddress {
  let decoded: { prefix: string; words: number[] };
  try {
    decoded = bech32m.decode(address, BECH32_LIMIT);
  } catch (err) {
    let bech32Ok = false;
    try {
      bech32.decode(address, BECH32_LIMIT);
      bech32Ok = true;
    } catch {
      bech32Ok = false;
    }
    if (bech32Ok) {
      throw new P2mrError(
        'ADDRESS_WRONG_CHECKSUM_VARIANT',
        'address uses a bech32 checksum; BIP-350 requires bech32m for witness versions >= 1',
      );
    }
    throw new P2mrError(
      'INVALID_ADDRESS',
      `not a valid bech32m address: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const { prefix, words } = decoded;
  assert(words.length >= 1, 'INVALID_ADDRESS', 'address data part is empty');

  const witnessVersion = words[0] as number;
  assert(
    witnessVersion === P2MR_WITNESS_VERSION,
    'ADDRESS_WRONG_WITNESS_VERSION',
    `P2MR requires witness version 2, got ${witnessVersion}`,
  );

  const networks = HRP_NETWORKS[prefix];
  assert(networks !== undefined, 'ADDRESS_WRONG_HRP', `unknown hrp \`${prefix}\``);
  if (options.network !== undefined) {
    assert(
      prefix === hrpFor(options.network),
      'ADDRESS_WRONG_HRP',
      `address hrp \`${prefix}\` does not match expected network ${options.network} (hrp \`${hrpFor(options.network)}\`)`,
    );
  }

  let program: Uint8Array;
  try {
    program = Uint8Array.from(bech32m.fromWords(words.slice(1)));
  } catch (err) {
    throw new P2mrError(
      'INVALID_ADDRESS',
      `failed to decode the witness program: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  assert(
    program.length === 32,
    'ADDRESS_WRONG_PROGRAM_LENGTH',
    `P2MR witness program must be 32 bytes, got ${program.length}`,
  );

  return { hrp: prefix, networks, witnessVersion, merkleRoot: program };
}
