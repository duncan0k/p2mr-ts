/**
 * OP_CHECKMLDSA44 on a real node (gate G1 of the M1 design): template outputs, signatures,
 * witnesses and transactions built by this library are handed to a regtest node running the M1
 * patch series. The node must accept every valid spend into its mempool and a block, and reject
 * each invalid one with the reason recorded next to it here, which must go with this library's own
 * verdict. A second implementation, the Python test framework of the same Core tree, signs one
 * spend and checks another. The run also checks, on the node, the wallet rules around activation:
 * the gate at H + 6, the protection status through a reorganization below H, the funding lock time,
 * and the mempool dropping a spend of the opcode when the chain goes back below H.
 *
 * Like `ark0-spend.ts` this is an interoperability check, not part of `npm test`. It needs:
 *
 * - `G1_SSH`: an ssh target from which `G1_CLI` runs;
 * - `G1_CLI`: the command that runs `bitcoin-cli` against the node, e.g. through `kubectl exec -i`;
 *   the node must be a fresh regtest node with `-testactivationheight=p2mr_mldsa44@200` and a
 *   wallet build (it mines from genesis);
 * - `G1_CORE_FUNCTIONAL`: the `test/functional` directory of that Core tree, for
 *   `examples/g1_python_sign.py`;
 * - optionally `G1_PYTHON` (default `python`) and `G1_OUT` (default `g1-regtest.result.json`).
 *
 * Every key is derived from a fixed label, so the run can be repeated; nothing of value is at stake
 * on regtest.
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import {
  assembleMldsa44Witness,
  bytesToHex,
  computeTxid,
  concatBytes,
  createMldsa44Output,
  decodeTransaction,
  encodeP2mrAddress,
  encodeTransaction,
  hexToBytes,
  isFinalAtHeight,
  MLDSA44_CONTEXT,
  mldsa44ActivationHeight,
  mldsa44Keygen,
  mldsa44MerkleRoot,
  mldsa44ProtectionStatus,
  mldsa44Sighash,
  mldsa44Sign,
  mldsa44Verify,
  P2mrError,
  p2mrScriptPathSighash,
  reverseBytes,
  signMldsa44Input,
  splitMldsa44Signature,
  withMldsa44FundingLockTime,
} from '../src/index.js';
import type { Mldsa44KeyPair, Mldsa44Output, SpentOutput, Transaction, TxOutput } from '../src/index.js';

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === '') throw new Error(`Missing environment variable ${name}`);
  return value;
}

const SSH = requireEnv('G1_SSH');
const CLI = requireEnv('G1_CLI');
const CORE_FUNCTIONAL = requireEnv('G1_CORE_FUNCTIONAL');
const PYTHON = process.env['G1_PYTHON'] ?? 'python';
const OUT = process.env['G1_OUT'] ?? 'g1-regtest.result.json';
const HERE = dirname(fileURLToPath(import.meta.url));
const EXPECTED_H = 200;
const FEE = 20_000n;
const WALLET = 'g1';

// ---------------------------------------------------------------------------------------------
// The node

class RpcError extends Error {}

function rpc(method: string, args: readonly string[] = [], wallet = false): string {
  const cmd = `${CLI}${wallet ? ` -rpcwallet=${WALLET}` : ''} -stdin ${method}`;
  try {
    return execFileSync('ssh', ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=20', SSH, cmd], {
      input: args.length === 0 ? '' : `${args.join('\n')}\n`,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch (err) {
    const e = err as { stderr?: string; message?: string };
    throw new RpcError(`${method}: ${(e.stderr ?? e.message ?? '').trim()}`);
  }
}

function rpcJson<T>(method: string, args: readonly string[] = [], wallet = false): T {
  return JSON.parse(rpc(method, args, wallet)) as T;
}

function mine(n: number, address: string): void {
  if (n > 0) rpc('generatetoaddress', [String(n), address]);
}

function tip(): number {
  return Number(rpc('getblockcount'));
}

function scriptPubKeyOf(address: string): Uint8Array {
  return hexToBytes(rpcJson<{ scriptPubKey: string }>('validateaddress', [address]).scriptPubKey);
}

function sats(btc: number): bigint {
  return BigInt(Math.round(btc * 1e8));
}

function btc(amount: bigint): number {
  return Number(amount) / 1e8;
}

interface Utxo {
  readonly txid: string;
  readonly vout: number;
  readonly amount: bigint;
  readonly scriptPubKey: Uint8Array;
}

/** The output of `txid` paying `scriptPubKey`. */
function utxoOf(txid: string, scriptPubKey: Uint8Array): Utxo {
  const tx = rpcJson<{ vout: Array<{ n: number; value: number; scriptPubKey: { hex: string } }> }>(
    'getrawtransaction',
    [txid, '1'],
  );
  const out = tx.vout.find((o) => o.scriptPubKey.hex === bytesToHex(scriptPubKey));
  if (out === undefined) throw new Error(`${txid} pays nothing to ${bytesToHex(scriptPubKey)}`);
  return { txid, vout: out.n, amount: sats(out.value), scriptPubKey };
}

/** The height of the block on the active chain that confirmed `txid`; null when there is none or the node does not know the transaction. */
function confirmationHeight(txid: string): number | null {
  let tx: { blockhash?: string; confirmations?: number };
  try {
    tx = rpcJson<{ blockhash?: string; confirmations?: number }>('getrawtransaction', [txid, '1']);
  } catch (err) {
    // -5: no such mempool or blockchain transaction
    if (err instanceof RpcError && err.message.includes('error code: -5')) return null;
    throw err;
  }
  if (tx.blockhash === undefined || (tx.confirmations ?? 0) < 1) return null;
  return rpcJson<{ height: number }>('getblockheader', [tx.blockhash]).height;
}

function inMempool(txid: string): boolean {
  return rpcJson<string[]>('getrawmempool').includes(txid);
}

interface Acceptance {
  readonly allowed: boolean;
  readonly reason: string | null;
}

function testAcceptHex(hex: string): Acceptance {
  const [r] = rpcJson<Array<{ allowed: boolean; 'reject-reason'?: string }>>('testmempoolaccept', [JSON.stringify([hex])]);
  return { allowed: r?.allowed === true, reason: r?.['reject-reason'] ?? null };
}

function testAccept(tx: Transaction): Acceptance {
  return testAcceptHex(bytesToHex(encodeTransaction(tx)));
}

/** Try to mine `tx` into a block; the node's error message, or `accepted`. */
function blockWith(tx: Transaction, address: string): string {
  try {
    rpc('generateblock', [address, JSON.stringify([bytesToHex(encodeTransaction(tx))])]);
    return 'accepted';
  } catch (err) {
    return (err as Error).message;
  }
}

function txidHex(tx: Transaction): string {
  return bytesToHex(reverseBytes(computeTxid(tx)));
}

/**
 * A transaction from the node's wallet, spending `coin` to `outputs`: nLockTime 0, and the input
 * replaceable (nSequence 0xfffffffd), given explicitly rather than left to the RPC's defaults.
 */
function walletTx(coin: WalletCoin, outputs: Record<string, number>): Transaction {
  const raw = rpc('createrawtransaction', [
    JSON.stringify([{ txid: coin.txid, vout: coin.vout }]),
    JSON.stringify(Object.entries(outputs).map(([a, v]) => ({ [a]: Number(v.toFixed(8)) }))),
    '0',
    'true',
  ]);
  return decodeTransaction(hexToBytes(raw));
}

function signByWallet(tx: Transaction): string {
  const signed = rpcJson<{ hex: string; complete: boolean }>('signrawtransactionwithwallet', [bytesToHex(encodeTransaction(tx, { witness: false }))], true);
  if (!signed.complete) throw new Error('the wallet did not complete the transaction');
  return signed.hex;
}

interface WalletCoin {
  readonly txid: string;
  readonly vout: number;
  readonly amount: number;
  readonly height: number;
}

// ---------------------------------------------------------------------------------------------
// The Core test framework, run locally

interface PythonSigned {
  message: string;
  signature: string;
  public_key: string;
}

function python<T>(request: Record<string, unknown>): T {
  const stdout = execFileSync(PYTHON, [resolve(HERE, 'g1_python_sign.py')], {
    input: JSON.stringify(request),
    encoding: 'utf8',
    env: { ...process.env, G1_CORE_FUNCTIONAL: CORE_FUNCTIONAL },
    maxBuffer: 16 * 1024 * 1024,
  });
  return JSON.parse(stdout) as T;
}

function spentJson(spentOutputs: readonly SpentOutput[]): Array<{ amount: number; script_pubkey: string }> {
  return spentOutputs.map((o) => ({ amount: Number(o.amount), script_pubkey: bytesToHex(o.scriptPubKey) }));
}

// ---------------------------------------------------------------------------------------------
// Building spends

function seedOf(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(`g1-regtest ${label}`));
}

function key(label: string): Mldsa44KeyPair {
  return mldsa44Keygen(seedOf(label));
}

/** An unsigned transaction spending `inputs` to one output. */
function spendTx(inputs: readonly Utxo[], to: Uint8Array): { tx: Transaction; spentOutputs: SpentOutput[] } {
  const total = inputs.reduce((sum, u) => sum + u.amount, 0n);
  const outputs: TxOutput[] = [{ amount: total - FEE, scriptPubKey: to }];
  const tx: Transaction = {
    version: 2,
    locktime: 0,
    inputs: inputs.map((u) => ({ txid: reverseBytes(hexToBytes(u.txid)), vout: u.vout, sequence: 0xfffffffd })),
    outputs,
  };
  return { tx, spentOutputs: inputs.map((u) => ({ amount: u.amount, scriptPubKey: u.scriptPubKey })) };
}

function withWitness(tx: Transaction, index: number, witness: Uint8Array[]): Transaction {
  return {
    ...tx,
    inputs: tx.inputs.map((input, i) => (i === index ? { ...input, witness } : { ...input, witness: input.witness ?? [] })),
  };
}

/** A valid S1 spend of `u` by `k` to `to`, signed by this library. */
function validS1Spend(u: Utxo, out: Mldsa44Output, k: Mldsa44KeyPair, to: Uint8Array): Transaction {
  const { tx, spentOutputs } = spendTx([u], to);
  const signature = signMldsa44Input({ secretKey: k.secretKey, tx, inputIndex: 0, spentOutputs, leafScript: out.templateLeaf.script });
  return withWitness(tx, 0, assembleMldsa44Witness({ signature, leafScript: out.templateLeaf.script, controlBlock: out.templateLeaf.controlBlock }));
}

/** Five chunks of any sizes, for witnesses the library refuses to assemble. */
function rawWitness(chunks: Uint8Array[], out: Mldsa44Output, below: Uint8Array[] = []): Uint8Array[] {
  return [...below, ...chunks, out.templateLeaf.script, out.templateLeaf.controlBlock];
}

function cut(sig: Uint8Array, sizes: readonly number[]): Uint8Array[] {
  const out: Uint8Array[] = [];
  let pos = 0;
  for (const size of sizes) {
    out.push(sig.slice(pos, pos + size));
    pos += size;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The run

const results: Array<Record<string, unknown>> = [];
function record(step: string, data: Record<string, unknown>): void {
  results.push({ step, ...data });
  console.log(`${step}: ${JSON.stringify(data)}`);
}
function check(condition: boolean, what: string): void {
  if (!condition) {
    writeFileSync(OUT, `${JSON.stringify({ failed: what, results }, null, 1)}\n`);
    throw new Error(`G1 check failed: ${what}`);
  }
}

function codeOf(fn: () => unknown): string | null {
  try {
    fn();
    return null;
  } catch (err) {
    return err instanceof P2mrError ? err.code : String(err);
  }
}

const SCRIPT_FAILED = (reason: string) => `mempool-script-verify-flag-failed (${reason})`;

function main(): void {
  const network = rpcJson<{ subversion: string }>('getnetworkinfo');
  const H = mldsa44ActivationHeight(rpcJson('getdeploymentinfo'));
  record('node', { subversion: network.subversion, activationHeight: H });
  check(H === EXPECTED_H, `the node reports activation height ${String(H)}, expected ${EXPECTED_H}`);
  const h = H as number;

  rpc('createwallet', [WALLET], false);
  const miner = rpc('getnewaddress', ['', 'bech32m'], true);
  mine(101, miner);

  // 1. The activation gate against the node's own state
  const gate = (): string | null =>
    codeOf(() => createMldsa44Output({ publicKey: key('gate').publicKey, network: 'regtest', chain: { activationHeight: h, tipHeight: tip() } }));
  const at101 = gate();

  // An output funded long before H, for the mempool check in step 6. The gate refuses to build it
  // now, so its address is computed from the parts; the same key gives the same address later.
  const kEarly = key('early');
  const earlyAddress = encodeP2mrAddress(mldsa44MerkleRoot(kEarly.publicKey), 'regtest');
  mine(150 - tip(), miner);
  const earlyFundingTxid = rpc('sendtoaddress', [earlyAddress, '1'], true);
  mine(1, miner);
  const earlyAt = confirmationHeight(earlyFundingTxid);
  record('funded before H', { address: earlyAddress, confirmedAt: earlyAt });
  check(earlyAt !== null && earlyAt < h - 2, 'the early output confirms below the height the reorganization goes back to');

  mine(h + 5 - tip(), miner);
  const atH5 = gate();
  mine(1, miner);
  const atH6 = gate();
  record('gate', { tip101: at101, tipHplus5: atH5, tipHplus6: atH6 });
  check(at101 === 'MLDSA44_NOT_ACTIVE' && atH5 === 'MLDSA44_NOT_ACTIVE' && atH6 === null, 'the gate opens at H + 6 exactly');

  // 2. Template outputs, funded by the node's wallet
  const chain = { activationHeight: h, tipHeight: tip() };
  const k = {
    a: key('a'), b: key('b'), c: key('c'), d: key('d'), neg: key('neg'), negS2: key('negS2'), late: key('late'), lock: key('lock'),
  };
  const schnorrSecret = seedOf('schnorr');
  const xonly = schnorr.getPublicKey(schnorrSecret);
  const o = {
    a: createMldsa44Output({ publicKey: k.a.publicKey, network: 'regtest', chain }),
    b: createMldsa44Output({ publicKey: k.b.publicKey, xonlyPubkey: xonly, network: 'regtest', chain }),
    c: createMldsa44Output({ publicKey: k.c.publicKey, network: 'regtest', chain }),
    d: createMldsa44Output({ publicKey: k.d.publicKey, network: 'regtest', chain }),
    neg: createMldsa44Output({ publicKey: k.neg.publicKey, network: 'regtest', chain }),
    negS2: createMldsa44Output({ publicKey: k.negS2.publicKey, xonlyPubkey: xonly, network: 'regtest', chain }),
    late: createMldsa44Output({ publicKey: k.late.publicKey, network: 'regtest', chain }),
    lock: createMldsa44Output({ publicKey: k.lock.publicKey, network: 'regtest', chain }),
  };
  const early = createMldsa44Output({ publicKey: kEarly.publicKey, network: 'regtest', chain });
  check(early.address === earlyAddress, 'the address computed from the parts is the template output');

  const funded = ['a', 'b', 'c', 'd', 'neg', 'negS2'] as const;
  const amounts = Object.fromEntries(funded.map((n) => [o[n].address, 1]));
  const fundingTxid = rpc('sendmany', ['', JSON.stringify(amounts)], true);
  const status = (n: keyof typeof o, confirmationHeight: number | null) =>
    mldsa44ProtectionStatus({
      scriptPubKey: o[n].scriptPubKey,
      publicKey: k[n].publicKey,
      ...(n === 'b' || n === 'negS2' ? { xonlyPubkey: xonly } : {}),
      confirmationHeight,
      activationHeight: h,
    });
  const pendingBefore = funded.map((n) => status(n, confirmationHeight(fundingTxid)));
  mine(1, miner);
  const fundedAt = confirmationHeight(fundingTxid);
  const statusAfter = funded.map((n) => status(n, fundedAt));
  record('funding', { txid: fundingTxid, addressA: o.a.address, before: pendingBefore, confirmedAt: fundedAt, after: statusAfter });
  check(pendingBefore.every((s) => s === 'pending') && statusAfter.every((s) => s === 'protected'), 'pending, then protected');
  const u = Object.fromEntries(funded.map((n) => [n, utxoOf(fundingTxid, o[n].scriptPubKey)])) as Record<(typeof funded)[number], Utxo>;
  const payTo = scriptPubKeyOf(rpc('getnewaddress', ['', 'bech32'], true));

  // 3. Valid spends
  const accepted: string[] = [];
  const submit = (name: string, tx: Transaction, extra: Record<string, unknown> = {}): void => {
    const r = testAccept(tx);
    record(`valid ${name}`, { txid: txidHex(tx), serializedBytes: encodeTransaction(tx).length, ...r, ...extra });
    check(r.allowed, `${name} is accepted`);
    rpc('sendrawtransaction', [bytesToHex(encodeTransaction(tx))]);
    accepted.push(txidHex(tx));
  };

  {
    const { tx, spentOutputs } = spendTx([u.a], payTo);
    const signature = signMldsa44Input({ secretKey: k.a.secretKey, tx, inputIndex: 0, spentOutputs, leafScript: o.a.templateLeaf.script });
    const witness = assembleMldsa44Witness({ signature, leafScript: o.a.templateLeaf.script, controlBlock: o.a.templateLeaf.controlBlock });
    const byPython = python<{ message: string; valid: boolean }>({
      mode: 'verify',
      tx: bytesToHex(encodeTransaction(tx, { witness: false })),
      spent: spentJson(spentOutputs),
      index: 0,
      leaf: bytesToHex(o.a.templateLeaf.script),
      public_key: bytesToHex(k.a.publicKey),
      signature: bytesToHex(signature),
    });
    const message = bytesToHex(mldsa44Sighash({ tx, inputIndex: 0, spentOutputs, leafScript: o.a.templateLeaf.script }));
    check(byPython.valid && byPython.message === message, 'the Python framework verifies the noble signature over the same message');
    submit('S1 (hedged, @noble/post-quantum)', withWitness(tx, 0, witness), { pythonVerifies: byPython.valid });
  }
  {
    const { tx, spentOutputs } = spendTx([u.b], payTo);
    const leafScript = o.b.templateLeaf.script;
    const signature = signMldsa44Input({ secretKey: k.b.secretKey, tx, inputIndex: 0, spentOutputs, leafScript, hashType: 0x81 });
    const m0 = p2mrScriptPathSighash({ tx, inputIndex: 0, spentOutputs, leafHash: o.b.templateLeaf.leafHash, hashType: 0x01 });
    const schnorrSignature = concatBytes(schnorr.sign(m0, schnorrSecret), Uint8Array.of(0x01));
    const witness = assembleMldsa44Witness({ signature, schnorrSignature, leafScript, controlBlock: o.b.templateLeaf.controlBlock });
    submit('S2 (0x81 ML-DSA-44, 0x01 BIP-340)', withWitness(tx, 0, witness));
  }
  {
    const { tx, spentOutputs } = spendTx([u.c], payTo);
    const leafScript = o.c.templateLeaf.script;
    const signed = python<PythonSigned>({
      mode: 'sign',
      tx: bytesToHex(encodeTransaction(tx, { witness: false })),
      spent: spentJson(spentOutputs),
      index: 0,
      leaf: bytesToHex(leafScript),
      seed: bytesToHex(seedOf('c')),
      hash_type: 0,
    });
    const message = mldsa44Sighash({ tx, inputIndex: 0, spentOutputs, leafScript });
    check(signed.public_key === bytesToHex(k.c.publicKey), 'the same seed gives the same key in both implementations');
    check(signed.message === bytesToHex(message), 'both implementations compute the same message');
    const signature = hexToBytes(signed.signature);
    check(mldsa44Verify(k.c.publicKey, message, signature), '@noble/post-quantum verifies the Python signature');
    const deterministic = mldsa44Sign(k.c.secretKey, message, { extraEntropy: false });
    const witness = assembleMldsa44Witness({ signature, leafScript, controlBlock: o.c.templateLeaf.controlBlock });
    submit('S1 signed by the Python test framework', withWitness(tx, 0, witness), {
      nobleVerifies: true,
      sameDeterministicSignature: bytesToHex(deterministic) === signed.signature,
    });
  }
  {
    // One P2MR input and one P2TR input of the node's wallet in the same transaction
    const walletCoin = rpcJson<Array<{ txid: string; vout: number; amount: number; scriptPubKey: string }>>('listunspent', ['101'], true).find(
      (c) => c.scriptPubKey.startsWith('5120') && c.amount >= 1,
    );
    check(walletCoin !== undefined, 'the wallet has a mature P2TR coin');
    const coin = walletCoin as NonNullable<typeof walletCoin>;
    const { tx, spentOutputs } = spendTx(
      [u.d, { txid: coin.txid, vout: coin.vout, amount: sats(coin.amount), scriptPubKey: hexToBytes(coin.scriptPubKey) }],
      payTo,
    );
    const signature = signMldsa44Input({ secretKey: k.d.secretKey, tx, inputIndex: 0, spentOutputs, leafScript: o.d.templateLeaf.script });
    const witness = assembleMldsa44Witness({ signature, leafScript: o.d.templateLeaf.script, controlBlock: o.d.templateLeaf.controlBlock });
    const signedByWallet = rpcJson<{ hex: string; complete: boolean }>(
      'signrawtransactionwithwallet',
      [
        bytesToHex(encodeTransaction(withWitness(tx, 0, witness))),
        JSON.stringify([{ txid: u.d.txid, vout: u.d.vout, scriptPubKey: bytesToHex(u.d.scriptPubKey), amount: btc(u.d.amount) }]),
      ],
      true,
    );
    check(signedByWallet.complete, 'the wallet completes the mixed transaction');
    submit('S1 next to a P2TR input of the wallet', decodeTransaction(hexToBytes(signedByWallet.hex)));
  }

  // 4. Invalid spends of one output: the node's reason, which must be the expected one, next to
  //    this library's verdict
  const negatives: Array<Record<string, unknown>> = [];
  const refused = (name: string, library: string, expectLibrary: string, tx: Transaction, expectReason: string): void => {
    const r = testAccept(tx);
    negatives.push({ case: name, library, ...r });
    check(library === expectLibrary, `${name}: this library says ${library}, expected ${expectLibrary}`);
    check(!r.allowed && r.reason === expectReason, `${name}: the node says ${String(r.reason)}, expected ${expectReason}`);
  };
  {
    const { tx, spentOutputs } = spendTx([u.neg], payTo);
    const leafScript = o.neg.templateLeaf.script;
    const m1 = mldsa44Sighash({ tx, inputIndex: 0, spentOutputs, leafScript });
    const m0 = p2mrScriptPathSighash({ tx, inputIndex: 0, spentOutputs, leafHash: o.neg.templateLeaf.leafHash });
    const good = mldsa44Sign(k.neg.secretKey, m1, { extraEntropy: false });
    const flipped = good.slice();
    flipped[100] = (flipped[100] as number) ^ 0x01;
    const sigCases: Array<[string, Uint8Array]> = [
      ['one bit of the signature flipped', flipped],
      ['another context string', ml_dsa44.sign(m1, k.neg.secretKey, { context: new TextEncoder().encode('P2MR/MLDSA44/EXP1'), extraEntropy: false })],
      ['the key_version 0 message', mldsa44Sign(k.neg.secretKey, m0, { extraEntropy: false })],
      ['HashML-DSA with SHA-256', ml_dsa44.prehash(sha256).sign(m1, k.neg.secretKey, { context: MLDSA44_CONTEXT, extraEntropy: false })],
      ['another key', mldsa44Sign(k.a.secretKey, m1, { extraEntropy: false })],
    ];
    for (const [name, sig] of sigCases) {
      const verdict = mldsa44Verify(k.neg.publicKey, m1, sig) ? 'valid' : 'invalid';
      refused(name, verdict, 'invalid', withWitness(tx, 0, rawWitness(splitMldsa44Signature(sig), o.neg)), SCRIPT_FAILED('Invalid ML-DSA-44 signature'));
    }
    const empty = withWitness(tx, 0, rawWitness(cut(new Uint8Array(0), [0, 0, 0, 0, 0]), o.neg));
    refused(
      'an empty signature (five empty chunks)',
      codeOf(() => splitMldsa44Signature(new Uint8Array(0))) ?? 'accepted',
      'MLDSA44_INVALID_SIGNATURE_SIZE',
      empty,
      SCRIPT_FAILED('Script evaluated without error but finished with a false/empty top stack element'),
    );
    // Policy stops a 519-byte chunk before the script runs (only the exact chunk sizes are exempt
    // from the 80-byte limit); the block below shows the consensus error
    const short = withWitness(tx, 0, rawWitness(cut(good.subarray(1), [519, 520, 520, 520, 340]), o.neg));
    refused('a 519-byte first chunk', codeOf(() => splitMldsa44Signature(good.subarray(1))) ?? 'accepted', 'MLDSA44_INVALID_SIGNATURE_SIZE', short, 'bad-witness-nonstandard');
    const zeroType = concatBytes(good, Uint8Array.of(0x00));
    refused(
      'an explicit 0x00 hash type',
      codeOf(() => splitMldsa44Signature(zeroType)) ?? 'accepted',
      'INVALID_HASH_TYPE',
      withWitness(tx, 0, rawWitness(cut(zeroType, [520, 520, 520, 520, 341]), o.neg)),
      SCRIPT_FAILED('Invalid ML-DSA-44 signature hash type'),
    );
    // At the block level
    const blockFlipped = blockWith(withWitness(tx, 0, rawWitness(splitMldsa44Signature(flipped), o.neg)), miner);
    const blockShort = blockWith(short, miner);
    record('blocks with invalid spends', { flippedSignature: blockFlipped, shortChunk: blockShort });
    check(blockFlipped.includes('block-script-verify-flag-failed (Invalid ML-DSA-44 signature)'), 'the block with the flipped signature is refused for its script');
    check(blockShort.includes('block-script-verify-flag-failed (Invalid ML-DSA-44 signature chunk size)'), 'the block with the short chunk is refused for the chunk size');
  }
  {
    const { tx, spentOutputs } = spendTx([u.negS2], payTo);
    const leafScript = o.negS2.templateLeaf.script;
    const signature = signMldsa44Input({ secretKey: k.negS2.secretKey, tx, inputIndex: 0, spentOutputs, leafScript });
    const m1 = mldsa44Sighash({ tx, inputIndex: 0, spentOutputs, leafScript });
    const wrongSchnorr = schnorr.sign(m1, schnorrSecret);
    const m0 = p2mrScriptPathSighash({ tx, inputIndex: 0, spentOutputs, leafHash: o.negS2.templateLeaf.leafHash });
    const verdict = schnorr.verify(wrongSchnorr, m0, xonly) ? 'valid' : 'invalid BIP-340 signature';
    const witness = assembleMldsa44Witness({ signature, schnorrSignature: wrongSchnorr, leafScript, controlBlock: o.negS2.templateLeaf.controlBlock });
    refused('S2 with a BIP-340 signature over the key_version 1 message', verdict, 'invalid BIP-340 signature', withWitness(tx, 0, witness), SCRIPT_FAILED('Invalid Schnorr signature'));
  }
  for (const n of negatives) record('invalid', n);

  // 5. The valid spends confirm
  mine(1, miner);
  const confirmedAt = accepted.map((txid) => confirmationHeight(txid));
  record('confirmed', { txids: accepted, heights: confirmedAt });
  check(confirmedAt.every((x) => x !== null), 'every valid spend is in a block');

  // 6. A reorganization below H. Coins for it: coinbases at height 90 or lower, which the main
  //    chain never spent and which are mature at H - 2, so that going back and forth cannot
  //    invalidate or conflict with anything.
  const mainTip = tip();
  const coins = rpcJson<Array<{ txid: string; vout: number; amount: number; confirmations: number }>>('listunspent', ['1'], true)
    .map((c) => ({ txid: c.txid, vout: c.vout, amount: c.amount, height: mainTip - c.confirmations + 1 }))
    .filter((c) => c.height <= 90)
    .sort((a, b) => a.height - b.height);
  check(coins.length >= 3, 'three old coins for the reorganization');
  const [coinControl, coinLock, coinDeposit] = coins as [WalletCoin, WalletCoin, WalletCoin];

  // 6a. Left unconfirmed in the mempool at the tip: a spend of the opcode whose parent confirmed
  //     long before H; a transaction unrelated to it; and a funding transaction the wallet built
  //     with this library's lock time, final at the tip since H is below the next height
  const earlySpend = validS1Spend(utxoOf(earlyFundingTxid, early.scriptPubKey), early, kEarly, payTo);
  const earlySpendTxid = rpc('sendrawtransaction', [bytesToHex(encodeTransaction(earlySpend))]);
  const controlTxid = rpc('sendrawtransaction', [signByWallet(walletTx(coinControl, { [miner]: coinControl.amount - 0.0002 }))]);
  const lockTx = withMldsa44FundingLockTime(walletTx(coinLock, { [o.lock.address]: 1, [miner]: coinLock.amount - 1 - 0.0002 }), h);
  const lockHex = signByWallet(lockTx);
  const lockSigned = decodeTransaction(hexToBytes(lockHex));
  const lockTxid = txidHex(lockSigned);
  record('funding lock time as signed', { locktime: lockSigned.locktime, sequences: lockSigned.inputs.map((i) => i.sequence) });
  check(lockSigned.locktime === h && lockSigned.inputs.some((i) => i.sequence !== 0xffffffff), 'the signed transaction carries nLockTime H and a non-final input');
  rpc('sendrawtransaction', [lockHex]);
  check(inMempool(earlySpendTxid) && inMempool(controlTxid) && inMempool(lockTxid), 'all three wait in the mempool at the tip');

  const hashBelow = rpc('getblockhash', [String(h - 1)]);
  rpc('invalidateblock', [hashBelow]);
  const tipBelow = tip();
  const spendDropped = !inMempool(earlySpendTxid);
  const controlKept = inMempool(controlTxid);
  const lockDropped = !inMempool(lockTxid);
  record('reorganization below H: the mempool', { mainTip, tipAfterInvalidate: tipBelow, earlySpendTxid, spendDropped, controlTxid, controlKept, lockTxid, lockDropped });
  check(tipBelow === h - 2, 'the tip is H - 2');
  check(spendDropped && controlKept, 'the spend of the opcode is dropped and the unrelated transaction kept');
  check(lockDropped, 'the locked funding transaction leaves the mempool once it is non-final');

  // 6b. A payment to an address handed out earlier, confirmed below H, is unprotected
  const depositHex = signByWallet(walletTx(coinDeposit, { [o.late.address]: 0.5, [miner]: coinDeposit.amount - 0.5 - 0.0002 }));
  const depositTxid = rpc('sendrawtransaction', [depositHex]);
  const lateStatus = (at: number | null) =>
    mldsa44ProtectionStatus({ scriptPubKey: o.late.scriptPubKey, publicKey: k.late.publicKey, confirmationHeight: at, activationHeight: h });
  const unconfirmed = lateStatus(confirmationHeight(depositTxid));
  mine(1, miner);
  const belowAt = confirmationHeight(depositTxid);
  const below = lateStatus(belowAt);

  // 6c. At tip H - 1 the next block is H: the locked funding transaction still cannot go into it,
  //     neither through the mempool nor in a block built with it
  const tipAtHminus1 = tip();
  const lockAtH = testAcceptHex(lockHex);
  const lockInBlockH = (() => {
    try {
      rpc('generateblock', [miner, JSON.stringify([lockHex])]);
      return 'accepted';
    } catch (err) {
      return (err as Error).message;
    }
  })();
  record('funding lock time at H', {
    tip: tipAtHminus1,
    finalForBlockH: isFinalAtHeight(lockSigned, h),
    ...lockAtH,
    blockH: lockInBlockH.slice(0, 200),
  });
  check(tipAtHminus1 === h - 1, 'the tip is H - 1');
  check(!isFinalAtHeight(lockSigned, h) && !lockAtH.allowed && lockAtH.reason === 'non-final', 'the mempool refuses it for block H');
  check(lockInBlockH.includes('bad-txns-nonfinal, non-final transaction'), 'a block at height H with it is invalid for its lock time');

  // 6d. Back to the chain with more work: the locked funding transaction and the payment confirm
  //     above H
  rpc('reconsiderblock', [hashBelow]);
  const tipBack = tip();
  const lockBack = testAcceptHex(lockHex);
  if (lockBack.allowed) rpc('sendrawtransaction', [lockHex]);
  if (!inMempool(depositTxid) && confirmationHeight(depositTxid) === null) rpc('sendrawtransaction', [depositHex]);
  mine(1, miner);
  const lockAt = confirmationHeight(lockTxid);
  const againAt = confirmationHeight(depositTxid);
  record('reorganization below H: status and lock time', {
    depositTxid,
    statusUnconfirmed: unconfirmed,
    confirmedBelowHAt: belowAt,
    statusBelowH: below,
    tipAfterReconsider: tipBack,
    confirmedAgainAt: againAt,
    statusAgain: lateStatus(againAt),
    lockedFundingAccepted: lockBack.allowed,
    lockedFundingConfirmedAt: lockAt,
  });
  check(unconfirmed === 'pending' && belowAt !== null && belowAt < h && below === 'unprotected', 'pending, then unprotected below H');
  check(tipBack === mainTip, 'the node goes back to the chain with more work');
  check(againAt !== null && againAt > h && lateStatus(againAt) === 'protected', 'protected again above H');
  check(lockBack.allowed && lockAt !== null && lockAt > h, 'the locked funding transaction confirms only above H');

  writeFileSync(OUT, `${JSON.stringify({ ok: true, results }, null, 1)}\n`);
  console.log(`G1 regtest run passed; results in ${OUT}`);
}

try {
  main();
} catch (err) {
  console.error(err);
  process.exit(1);
}
