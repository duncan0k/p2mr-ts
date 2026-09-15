/**
 * Cross-implementation P2MR script-path spend: the address, signature hash, witness and
 * transaction serialization are all produced by this library, the Schnorr signature is
 * produced independently by `@noble/curves`, and the transaction is handed to a Bitcoin
 * Core node running a BIP-360 patch to be validated and confirmed in a block.
 *
 * This example is an **interoperability check**, not part of the library: it needs two
 * experimental signet nodes on an ssh-reachable machine, so it stays out of `npm test`.
 * The library itself still does no networking and no signing: the network calls live
 * here, and signing uses an external library.
 *
 * Usage (node addresses and the wallet name all come from environment variables; no host
 * information is kept in the repository):
 *
 * ```bash
 * # one process end to end, the private key exists only in process memory
 * ARK0_SSH=user@host npx tsx examples/ark0-spend.ts run
 *
 * # two stages; the private key travels through an environment variable, never hits disk
 * ARK0_SSH=user@host ARK0_DEMO_PRIV=<64 hex chars> npx tsx examples/ark0-spend.ts prepare
 * ARK0_SSH=user@host ARK0_DEMO_PRIV=<64 hex chars> npx tsx examples/ark0-spend.ts spend
 * ```
 *
 * The private key travels only through an environment variable or process memory: it is
 * never written to a state file, never printed and never logged.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { schnorr } from '@noble/curves/secp256k1.js';
import {
  assembleScriptPathWitness,
  bytesToHex,
  computeTxid,
  computeWtxid,
  concatBytes,
  createP2mrOutput,
  decodeTransaction,
  encodeTransaction,
  hexToBytes,
  p2mrScriptPathSighash,
  reverseBytes,
  toBytes,
} from '../src/index.js';
import type { P2mrLeafOutput, Transaction, TxInput } from '../src/index.js';

type NodeName = 'A' | 'B';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === '') {
    throw new Error(`Missing environment variable ${name}`);
  }
  return value;
}

const SSH_TARGET = requireEnv('ARK0_SSH');
const CLI = process.env['ARK0_CLI'] ?? '~/bitcoin-p2mr/build/bin/bitcoin-cli';
const DATADIR: Readonly<Record<NodeName, string>> = {
  A: process.env['ARK0_DATADIR_A'] ?? '$HOME/.ark0/nodeA',
  B: process.env['ARK0_DATADIR_B'] ?? '$HOME/.ark0/nodeB',
};
const WALLET = process.env['ARK0_WALLET'] ?? 'ark0';
const STATE_PATH = process.env['ARK0_STATE'] ?? 'ark0-spend.state.json';
const FUND_BTC = process.env['ARK0_FUND_BTC'] ?? '0.1';
const FEE_SATS = BigInt(process.env['ARK0_FEE_SATS'] ?? '10000');

interface RpcOptions {
  /** Add `-rpcwallet=<wallet>`. */
  readonly wallet?: boolean;
  /** Pass arguments via `-stdin`, so quotes inside JSON arguments survive two shell layers. */
  readonly stdinArgs?: readonly string[];
}

interface PreparedState {
  readonly network: string;
  readonly address: string;
  readonly merkleRoot: string;
  readonly scriptPubKey: string;
  readonly xonlyPubkey: string;
  readonly leaves: ReadonlyArray<{
    readonly name: string;
    readonly script: string;
    readonly leafVersion: number;
    readonly leafHash: string;
    readonly controlBlock: string;
  }>;
  readonly funding: {
    readonly txid: string;
    readonly vout: number;
    readonly amountSats: string;
    readonly blockhash: string;
    readonly height: number;
  };
}

/** Run one bitcoin-cli command on the remote host; on an RPC error, rethrow stderr verbatim. */
function rpc(node: NodeName, args: readonly string[], options: RpcOptions = {}): string {
  const parts = [CLI, `-datadir=${DATADIR[node]}`, '-signet'];
  if (options.wallet === true) parts.push(`-rpcwallet=${WALLET}`);
  if (options.stdinArgs !== undefined) parts.push('-stdin');
  parts.push(...args);

  try {
    return execFileSync(
      'ssh',
      ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=20', SSH_TARGET, parts.join(' ')],
      {
        encoding: 'utf8',
        maxBuffer: 32 * 1024 * 1024,
        // By default execFileSync forwards child stderr straight to the parent; while polling,
        // the "transaction has not arrived yet" errors would scroll past as failure output,
        // so capture them into a pipe explicitly
        stdio: ['pipe', 'pipe', 'pipe'],
        ...(options.stdinArgs === undefined
          ? {}
          : { input: `${options.stdinArgs.join('\n')}\n` }),
      },
    ).trim();
  } catch (err) {
    const e = err as { stderr?: string; message?: string };
    const detail = (e.stderr ?? e.message ?? '').trim();
    throw new Error(`bitcoin-cli on node ${node} ${args[0] ?? ''} failed: ${detail}`);
  }
}

function rpcJson<T>(node: NodeName, args: readonly string[], options: RpcOptions = {}): T {
  return JSON.parse(rpc(node, args, options)) as T;
}

/** Display-order txid (the convention used by block explorers and RPC). */
function txidHex(tx: Transaction): string {
  return bytesToHex(reverseBytes(computeTxid(tx)));
}

function wtxidHex(tx: Transaction): string {
  return bytesToHex(reverseBytes(computeWtxid(tx)));
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Two-leaf tree: leaf A is `<x-only pubkey> OP_CHECKSIG`, leaf B is `OP_RETURN` (never satisfiable).
 *
 * Two leaves rather than one: a single-leaf tree has m=0 in the control block, so under BIP-360 a
 * root match alone succeeds and the script is never executed, which would not exercise signature
 * verification. This library also rejects a single leaf by default.
 */
function buildTree(priv: Uint8Array): {
  readonly xonly: Uint8Array;
  readonly address: string;
  readonly merkleRoot: Uint8Array;
  readonly scriptPubKey: Uint8Array;
  readonly leafA: P2mrLeafOutput;
  readonly leafB: P2mrLeafOutput;
} {
  const xonly = schnorr.getPublicKey(priv);
  const leafScriptA = concatBytes(Uint8Array.of(0x20), xonly, Uint8Array.of(0xac));
  const leafScriptB = Uint8Array.of(0x6a);

  const out = createP2mrOutput({
    scriptTree: [
      { script: leafScriptA, leafVersion: 0xc0 },
      { script: leafScriptB, leafVersion: 0xc0 },
    ],
    network: 'signet',
  });

  return {
    xonly,
    address: out.address,
    merkleRoot: out.merkleRoot,
    scriptPubKey: out.scriptPubKey,
    leafA: out.leaves[0] as P2mrLeafOutput,
    leafB: out.leaves[1] as P2mrLeafOutput,
  };
}

/** Wait for a transaction to confirm on the given node; return its block hash and height. */
async function waitForConfirmation(
  node: NodeName,
  txid: string,
  timeoutMs = 900_000,
): Promise<{ blockhash: string; height: number }> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const tx = rpcJson<{ confirmations?: number; blockhash?: string }>(node, [
        'getrawtransaction',
        txid,
        '1',
      ]);
      if ((tx.confirmations ?? 0) >= 1 && tx.blockhash !== undefined) {
        const header = rpcJson<{ height: number }>(node, ['getblockheader', tx.blockhash]);
        return { blockhash: tx.blockhash, height: header.height };
      }
    } catch {
      // The transaction has not reached this node yet, keep waiting
    }
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${txid} on node ${node}`);
    process.stdout.write('.');
    await sleep(5_000);
  }
}

/** Find the output of the funding transaction paying our scriptPubKey, with its exact sat amount. */
function findFundedOutput(
  rawHex: string,
  scriptPubKey: Uint8Array,
): { vout: number; amount: bigint } {
  const tx = decodeTransaction(hexToBytes(rawHex));
  const want = bytesToHex(scriptPubKey);
  const vout = tx.outputs.findIndex((o) => bytesToHex(o.scriptPubKey) === want);
  if (vout < 0) throw new Error('The funding transaction has no output paying that P2MR scriptPubKey');
  return { vout, amount: (tx.outputs[vout] as { amount: bigint }).amount };
}

async function prepare(priv: Uint8Array): Promise<PreparedState> {
  const tree = buildTree(priv);
  const cbLen = tree.leafA.controlBlock.length;

  console.log('--- P2MR output (all produced by p2mr-ts) ---');
  console.log(`address               ${tree.address}`);
  console.log(`merkle root           ${bytesToHex(tree.merkleRoot)}`);
  console.log(`scriptPubKey          ${bytesToHex(tree.scriptPubKey)}`);
  console.log(`x-only pubkey         ${bytesToHex(tree.xonly)}`);
  console.log(`leaf A script         ${bytesToHex(tree.leafA.script)}`);
  console.log(`leaf A leafHash       ${bytesToHex(tree.leafA.leafHash)}`);
  console.log(`leaf A control block  ${bytesToHex(tree.leafA.controlBlock)} (${cbLen} bytes)`);
  console.log(`leaf B script         ${bytesToHex(tree.leafB.script)}`);
  console.log(`leaf B leafHash       ${bytesToHex(tree.leafB.leafHash)}`);
  console.log(`leaf B control block  ${bytesToHex(tree.leafB.controlBlock)}`);

  console.log(`\n--- Sending ${FUND_BTC} BTC to ${tree.address} ---`);
  const fundTxid = rpc('A', ['sendtoaddress', tree.address, FUND_BTC], { wallet: true });
  console.log(`funding txid    ${fundTxid}`);
  process.stdout.write('waiting for confirmation ');
  const confirmed = await waitForConfirmation('A', fundTxid);
  console.log(`\nconfirmed block ${confirmed.blockhash} (height ${confirmed.height})`);

  const rawFund = rpc('A', ['getrawtransaction', fundTxid]);
  const funded = findFundedOutput(rawFund, tree.scriptPubKey);
  console.log(`vout / amount   ${funded.vout} / ${funded.amount} sat`);

  const state: PreparedState = {
    network: 'signet',
    address: tree.address,
    merkleRoot: bytesToHex(tree.merkleRoot),
    scriptPubKey: bytesToHex(tree.scriptPubKey),
    xonlyPubkey: bytesToHex(tree.xonly),
    leaves: [
      {
        name: 'csig',
        script: bytesToHex(tree.leafA.script),
        leafVersion: tree.leafA.leafVersion,
        leafHash: bytesToHex(tree.leafA.leafHash),
        controlBlock: bytesToHex(tree.leafA.controlBlock),
      },
      {
        name: 'ret',
        script: bytesToHex(tree.leafB.script),
        leafVersion: tree.leafB.leafVersion,
        leafHash: bytesToHex(tree.leafB.leafHash),
        controlBlock: bytesToHex(tree.leafB.controlBlock),
      },
    ],
    funding: {
      txid: fundTxid,
      vout: funded.vout,
      amountSats: funded.amount.toString(),
      blockhash: confirmed.blockhash,
      height: confirmed.height,
    },
  };

  // The state file holds no private key, only the publicly reviewable construction result
  writeFileSync(STATE_PATH, `${JSON.stringify(state, null, 2)}\n`, 'utf8');
  console.log(`\nConstruction result written to ${STATE_PATH} (no private key)`);
  return state;
}

async function spend(priv: Uint8Array, state: PreparedState): Promise<void> {
  const tree = buildTree(priv);
  if (tree.address !== state.address) {
    throw new Error('ARK0_DEMO_PRIV does not match the address in the state file');
  }

  // Destination: a fresh address from the node A wallet
  const destAddress = rpc('A', ['getnewaddress'], { wallet: true });
  const destInfo = rpcJson<{ scriptPubKey: string }>('A', ['getaddressinfo', destAddress]);
  const amountIn = BigInt(state.funding.amountSats);
  const amountOut = amountIn - FEE_SATS;
  if (amountOut <= 0n) throw new Error('Input amount is not enough to cover the fee');

  const tx: Transaction = {
    version: 2,
    locktime: 0,
    inputs: [
      {
        txid: reverseBytes(hexToBytes(state.funding.txid)),
        vout: state.funding.vout,
        sequence: 0xffffffff,
      },
    ],
    outputs: [{ amount: amountOut, scriptPubKey: toBytes(destInfo.scriptPubKey) }],
  };

  const spentOutputs = [{ amount: amountIn, scriptPubKey: toBytes(state.scriptPubKey) }];
  const digest = p2mrScriptPathSighash({
    tx,
    inputIndex: 0,
    spentOutputs,
    leafHash: tree.leafA.leafHash,
  });

  // Signing happens here and nowhere else, and it uses @noble/curves, not this library
  const signature = schnorr.sign(digest, priv);
  if (!schnorr.verify(signature, digest, tree.xonly)) {
    throw new Error('Local self-verification of the signature failed, nothing is sent out');
  }

  const witness = assembleScriptPathWitness({
    stack: [signature],
    leafScript: tree.leafA.script,
    controlBlock: tree.leafA.controlBlock,
  });
  const withWitness = (stack: readonly Uint8Array[]): Transaction => ({
    ...tx,
    inputs: [{ ...(tx.inputs[0] as TxInput), witness: stack }],
  });

  const signedTx = withWitness(witness);
  const rawHex = bytesToHex(encodeTransaction(signedTx, { witness: true }));

  // Negative case: flip the last byte of the signature, everything else byte-for-byte identical
  const badSig = Uint8Array.from(signature);
  badSig[badSig.length - 1] = (badSig[badSig.length - 1] as number) ^ 0x01;
  const badTx = withWitness(
    assembleScriptPathWitness({
      stack: [badSig],
      leafScript: tree.leafA.script,
      controlBlock: tree.leafA.controlBlock,
    }),
  );
  const badHex = bytesToHex(encodeTransaction(badTx, { witness: true }));

  console.log('\n--- Spend transaction (constructed and serialized by p2mr-ts) ---');
  console.log(`sighash digest  ${bytesToHex(digest)}`);
  console.log(`leaf A leafHash ${bytesToHex(tree.leafA.leafHash)}`);
  console.log(`signature       ${bytesToHex(signature)}`);
  console.log(`destination     ${destAddress}`);
  console.log(`amount          ${amountIn} - ${FEE_SATS} = ${amountOut} sat`);
  console.log(`txid (local)    ${txidHex(signedTx)}`);
  console.log(`wtxid (local)   ${wtxidHex(signedTx)}`);
  console.log(`raw tx          ${rawHex}`);

  // Run the negative case first: once the positive case is on chain, the negative case would
  // spend an already-spent output, and the reject reason would become a missing input rather
  // than a script verification failure
  console.log('\n--- Negative case: one signature byte flipped, mempool test only ---');
  console.log(`raw tx (neg)    ${badHex}`);
  console.log(rpc('B', ['testmempoolaccept'], { stdinArgs: [JSON.stringify([badHex])] }));

  console.log('\n--- testmempoolaccept on node B (positive case) ---');
  const okResult = rpc('B', ['testmempoolaccept'], { stdinArgs: [JSON.stringify([rawHex])] });
  console.log(okResult);
  const parsed = JSON.parse(okResult) as Array<{ allowed?: boolean; 'reject-reason'?: string }>;
  if (parsed[0]?.allowed !== true) {
    throw new Error(`Node B rejected this transaction: ${parsed[0]?.['reject-reason'] ?? 'unknown reason'}`);
  }

  console.log('\n--- Broadcast ---');
  const broadcastTxid = rpc('A', ['sendrawtransaction'], { stdinArgs: [rawHex] });
  if (broadcastTxid !== txidHex(signedTx)) {
    throw new Error(`Node txid differs from the locally computed one: ${broadcastTxid} vs ${txidHex(signedTx)}`);
  }
  console.log(`txid            ${broadcastTxid} (matches the local computeTxid)`);

  process.stdout.write('waiting for a block ');
  const mined = await waitForConfirmation('B', broadcastTxid);
  console.log(`\nconfirmed block ${mined.blockhash} (height ${mined.height})`);

  const verbose = rpcJson<{
    confirmations: number;
    hash: string;
    vsize: number;
    weight: number;
    vin: ReadonlyArray<{ txinwitness?: readonly string[] }>;
  }>('B', ['getrawtransaction', broadcastTxid, '1']);
  console.log(`confirmations   ${verbose.confirmations} (reported independently by node B)`);
  console.log(`wtxid (node)    ${verbose.hash}`);
  console.log(`vsize / weight  ${verbose.vsize} / ${verbose.weight}`);
  console.log(`txinwitness     ${JSON.stringify(verbose.vin[0]?.txinwitness ?? [], null, 2)}`);
  const spentCheck = rpc('B', ['gettxout', state.funding.txid, String(state.funding.vout)]);
  console.log(`gettxout (prev) ${spentCheck === '' ? 'null (already spent)' : spentCheck}`);
}

async function main(): Promise<void> {
  const mode = process.argv[2] ?? 'run';

  if (mode === 'run') {
    // One-shot key, exists only in the memory of this process
    const priv = schnorr.keygen().secretKey;
    const state = await prepare(priv);
    await spend(priv, state);
    return;
  }

  const priv = toBytes(requireEnv('ARK0_DEMO_PRIV'), 'ARK0_DEMO_PRIV');
  if (priv.length !== 32) throw new Error('ARK0_DEMO_PRIV must be 32 bytes (64 hex chars)');

  if (mode === 'prepare') {
    await prepare(priv);
    return;
  }
  if (mode === 'spend') {
    await spend(priv, JSON.parse(readFileSync(STATE_PATH, 'utf8')) as PreparedState);
    return;
  }
  throw new Error(`Unknown subcommand ${mode}; available: run | prepare | spend`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
