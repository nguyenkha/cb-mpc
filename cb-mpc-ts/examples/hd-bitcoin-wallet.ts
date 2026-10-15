/**
 * HD Bitcoin Wallet Demo (dry run, testnet P2WPKH, nothing is broadcast)
 *
 *   1. One HD keyset DKG per user
 *   2. Account xpub for m/84'/1'/0' (one MPC round per account)
 *   3. 5 receive addresses + 1 change address from the xpub (no MPC)
 *   4. A transaction spending 10 UTXOs spread over the 5 addresses
 *   5. Derive the 5 spending keys in one MPC round
 *   6. Sign the 10 inputs with 2-party ECDSA (batched per key, and one run per input)
 *   7. Verify every signature independently and finalize the witness
 *
 * Prints the time of each step. Both parties run in this process over an
 * in-memory transport (no network latency), on the WASM backend.
 *
 * Needs the dev dependencies @scure/btc-signer, @scure/bip32 and @noble/curves.
 */

import * as btc from "@scure/btc-signer";
import { HDKey } from "@scure/bip32";
import { secp256k1 } from "@noble/curves/secp256k1";
import { randomBytes } from "node:crypto";

import { initCbMpc, CbMpc, NID_secp256k1 } from "../dist/index";
import type { DataTransport } from "../dist/index";
import { createMockNetwork } from "./mock-transport";

const NET = btc.TEST_NETWORK;
const P: [string, string] = ["client", "server"];
const H = 0x80000000;
const ACCOUNT = [84 + H, 1 + H, 0 + H]; // m/84'/1'/0' (BIP84 testnet), hardened step = MPC VRF label
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** Run the same 2-party call on both parties over a fresh in-memory network. */
async function both<T>(ms: CbMpc[], fn: (m: CbMpc, t: DataTransport, i: number) => Promise<T>): Promise<[T, T]> {
  const net = createMockNetwork(2);
  return (await Promise.all(ms.map((m, i) => fn(m, net[i], i)))) as [T, T];
}
const times: [string, number][] = [];
async function step<T>(label: string, fn: () => Promise<T> | T): Promise<T> {
  const t0 = performance.now();
  const r = await fn();
  times.push([label, performance.now() - t0]);
  return r;
}
const compress = (sec1: Uint8Array) => { const o = new Uint8Array(33); o[0] = 0x02 | (sec1[64] & 1); o.set(sec1.slice(1, 33), 1); return o; };

// DER signature -> low-S DER (BIP62/146 standardness); MPC output may be high-S.
function lowS(der: Uint8Array): Uint8Array {
  const sig = secp256k1.Signature.fromDER(der);
  return sig.hasHighS() ? sig.normalizeS().toDERRawBytes() : der;
}

const ms = await Promise.all([initCbMpc(), initCbMpc()]);

// 1. One-time keyset DKG (per user).
const ks = await step("1. keyset DKG (one-time per user, MPC)", () =>
  both(ms, (m, t, i) => m.hdEcdsa2pDkg(t, i, P, NID_secp256k1)));

// 2. Account xpub (once per account, MPC) -> addresses without MPC.
const [node] = await step("2. account node / xpub (once per account, MPC)", () =>
  both(ms, (m, t, i) => m.hdEcdsa2pAccountNode(t, i, P, ks[i], ACCOUNT)));
const xpub = new HDKey({ publicKey: node.publicKey, chainCode: node.chainCode, versions: { private: 0x04358394, public: 0x043587cf } });

const RECEIVE = [0, 1, 2, 3, 4].map((i) => [0, i]);
const CHANGE = [1, 0];
const addrs = await step("3. derive 5 receive + 1 change address from xpub (no MPC)", () =>
  [...RECEIVE, CHANGE].map(([c, i]) => {
    const pub = xpub.deriveChild(c).deriveChild(i).publicKey!;
    return { path: [c, i], pub, ...btc.p2wpkh(pub, NET) };
  }));
const receive = addrs.slice(0, 5), change = addrs[5];

// 4. Fake UTXOs: 10 inputs spread over the 5 receive addresses (2 each), and the tx.
const destination = btc.p2wpkh(secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey(), true), NET).address!;
const utxos = Array.from({ length: 10 }, (_, k) => ({
  owner: receive[k % 5],
  txid: randomBytes(32),
  index: k % 3,
  amount: BigInt(20_000 + k * 1_337),
}));
const total = utxos.reduce((s, u) => s + u.amount, 0n);
const fee = 2_500n, sendAmount = 150_000n;
const tx = await step("4. build tx + 10 BIP143 sighashes (no MPC)", () => {
  const t = new btc.Transaction();
  for (const u of utxos) t.addInput({ txid: u.txid, index: u.index, witnessUtxo: { script: u.owner.script, amount: u.amount } });
  t.addOutputAddress(destination, sendAmount, NET);
  t.addOutputAddress(change.address!, total - sendAmount - fee, NET);
  return t;
});
const sighashes = utxos.map((u, i) => {
  const scriptCode = btc.OutScript.encode({ type: "pkh", hash: btc.p2wpkh(u.owner.pub, NET).hash });
  return tx.preimageWitnessV0(i, scriptCode, btc.SigHash.ALL, u.amount);
});

// 5. MPC: derive the 5 spending keys in one round.
const [k0, k1] = await step("5. MPC derive 5 keys (1 round, all paths)", () =>
  both(ms, (m, t, i) => m.hdEcdsa2pDerive(t, i, P, ks[i], ACCOUNT, RECEIVE)));
for (let j = 0; j < 5; j++) {
  const pub = compress(ms[0].ecdsa2pKeyInfo(k0[j]).publicKey);
  if (hex(pub) !== hex(receive[j].pub)) throw new Error(`MPC key ${j} != xpub child`);
}

// 6a. Sign grouped by key: 5 ECDSA-2P batch runs, 2 inputs each.
const sigsBatch: Uint8Array[] = new Array(10);
await step("6a. MPC sign 10 inputs, batched per key (5 runs x 2 sigs)", async () => {
  for (let j = 0; j < 5; j++) {
    const idx = utxos.map((u, i) => (u.owner === receive[j] ? i : -1)).filter((i) => i >= 0);
    const [s] = await both(ms, (m, t, i) => m.ecdsa2pSign(t, i, P, i ? k1[j] : k0[j], new Uint8Array(0), idx.map((n) => sighashes[n])));
    idx.forEach((n, x) => (sigsBatch[n] = s[x]));
  }
});

// 6b. Same, one ECDSA-2P run per input (10 runs).
const sigsSingle: Uint8Array[] = new Array(10);
await step("6b. MPC sign 10 inputs, one run per input (10 runs)", async () => {
  for (let n = 0; n < 10; n++) {
    const j = receive.indexOf(utxos[n].owner);
    const [s] = await both(ms, (m, t, i) => m.ecdsa2pSign(t, i, P, i ? k1[j] : k0[j], new Uint8Array(0), [sighashes[n]]));
    sigsSingle[n] = s[0];
  }
});

// 7. Verify every signature independently, finalize the witness, extract raw tx.
const raw = await step("7. verify (noble) + finalize + extract tx (no MPC)", () => {
  for (const sigs of [sigsBatch, sigsSingle]) {
    sigs.forEach((der, n) => {
      if (!secp256k1.verify(secp256k1.Signature.fromDER(der).toCompactRawBytes(), sighashes[n], utxos[n].owner.pub, { lowS: false }))
        throw new Error(`signature for input ${n} does not verify`);
    });
  }
  sigsBatch.forEach((der, n) => {
    tx.updateInput(n, { partialSig: [[utxos[n].owner.pub, new Uint8Array([...lowS(der), btc.SigHash.ALL])]] });
  });
  tx.finalize();
  return tx.extract();
});

console.log(`account xpub (tpub): ${xpub.publicExtendedKey}`);
console.log(`receive: ${receive.map((a) => a.address).join(", ")}`);
console.log(`change : ${change.address}   destination: ${destination}`);
console.log(`tx: ${tx.inputsLength} inputs, ${tx.outputsLength} outputs, ${raw.length} bytes, vsize ${tx.vsize}, txid ${tx.id}`);
console.log(`all 10 signatures verified (batched and single), witness finalized; NOT broadcast\n`);
const w = Math.max(...times.map(([l]) => l.length));
for (const [l, ms_] of times) console.log(`${l.padEnd(w)}  ${ms_.toFixed(0).padStart(7)} ms`);
const signTotal = times.find(([l]) => l.startsWith("5."))![1] + times.find(([l]) => l.startsWith("6a."))![1];
console.log(`\nper spend (derive + batched sign): ${signTotal.toFixed(0)} ms   (both parties in one process, WASM, no network)`);
