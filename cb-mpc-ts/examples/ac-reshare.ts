/**
 * Access-structure keys and resharing (WASM backend), kexify 2-of-3 layout: iphone, mac (backup), server.
 *
 *   1. 2-of-2 keys made like kexify today (ecdsa2pDkg + refresh, ecKey2pDkg) are reshared to 2-of-3 with the same
 *      public key; every pair signs, refreshAc, every pair signs again.
 *   2. iphone lost: mac + server reshare a new generation; every pair signs; the lost iphone's old share does not
 *      combine with the new server share.
 *   3. 2-of-3 -> 2-of-2 (iphone, server).
 *   4. A wrong public key and an impersonating party are rejected.
 *
 * Run: bun run examples/ac-reshare.ts   (exits non-zero on failure, so it doubles as a test)
 */

import { createPublicKey, createHash, verify as nodeVerify } from "node:crypto";
import { initCbMpc, CbMpc, NID_secp256k1, NID_ED25519, thresholdOf, type AccessStructure } from "../dist/index";
import { createMockNetwork } from "./mock-transport";

const ALL = ["iphone", "mac", "server"];
const TWO_OF_THREE = thresholdOf(2, ALL);
const hash = new Uint8Array(createHash("sha256").update("ac-reshare").digest());
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

let passed = 0;
let failed = 0;
function check(ok: boolean, what: string): void {
  console.log(`   ${ok ? "ok  " : "FAIL"} ${what}`);
  ok ? passed++ : failed++;
}
async function rejects(p: Promise<unknown>): Promise<boolean> {
  try {
    await p;
    return false;
  } catch {
    return true;
  }
}

// One WASM instance per party (an instance runs one suspended protocol call at a time).
const inst: Record<string, CbMpc> = {};
for (const n of ALL) inst[n] = await initCbMpc();
const verifier = await initCbMpc();

/** Runs `fn(mpc, transport, index)` for each of `names` concurrently. */
async function run<T>(names: string[], fn: (mpc: CbMpc, t: any, i: number) => Promise<T>): Promise<T[]> {
  const t = createMockNetwork(names.length);
  return Promise.all(names.map((n, i) => fn(inst[n], t[i], i)));
}

function ed25519Verify(pub32: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub32]), format: "der", type: "spki" });
  return nodeVerify(null, msg, key, sig);
}

/** `pub`: compressed key from acKeyInfo, or SEC1 for ECDSA. */
function verifies(curve: number, pub: Uint8Array, sig: Uint8Array): boolean {
  if (sig.length === 0) return false;
  return curve === NID_ED25519 ? ed25519Verify(pub, hash, sig) : verifier.verifyDer(curve, pub, hash, sig);
}

type Keys = Record<string, Uint8Array>;

async function pairSigns(curve: number, pair: string[], keys: Keys, ac: AccessStructure, pub: Uint8Array) {
  try {
    const sigs = await run(pair, (m, t, i) => m.signAc(t, i, pair, keys[pair[i]], ac, hash, 0));
    return verifies(curve, pub, sigs[0]);
  } catch {
    return false;
  }
}

async function everyPairSigns(curve: number, label: string, keys: Keys, ac: AccessStructure, pub: Uint8Array) {
  const names = Object.keys(keys);
  for (let a = 0; a < names.length; a++)
    for (let b = a + 1; b < names.length; b++)
      check(await pairSigns(curve, [names[a], names[b]], keys, ac, pub), `${label}: ${names[a]}+${names[b]} signs`);
}

async function reshare(
  curve: number, names: string[], pub: Uint8Array, dealers: string[], xs: Keys, ac: AccessStructure,
): Promise<Keys> {
  const out = await run(names, (m, t, i) =>
    m.reshareFromAdditive(t, i, names, curve, pub, dealers, xs[names[i]] ?? null, ac),
  );
  const keys: Keys = {};
  names.forEach((n, i) => out[i].length && (keys[n] = out[i]));
  return keys;
}

async function refreshAll(keys: Keys, ac: AccessStructure): Promise<Keys> {
  const names = Object.keys(keys);
  const out = await run(names, (m, t, i) => m.refreshAc(t, i, names, keys[names[i]], ac, names));
  return Object.fromEntries(names.map((n, i) => [n, out[i]]));
}

for (const [cname, curve] of [["ECDSA secp256k1", NID_secp256k1], ["EdDSA Ed25519", NID_ED25519]] as const) {
  console.log(`\n== ${cname}`);
  const pair2p = ["iphone", "server"];

  // 1. 2-of-2 binding keys -> 2-of-3.
  let xs: Keys = {};
  let pubSec1: Uint8Array;
  if (curve === NID_secp256k1) {
    let k = await run(pair2p, (m, t, i) => m.ecdsa2pDkg(t, i, pair2p, curve));
    k = await run(pair2p, (m, t, i) => m.ecdsa2pRefresh(t, i, pair2p, k[i]));
    const info = pair2p.map((n, i) => inst[n].ecdsa2pKeyInfo(k[i]));
    pubSec1 = info[0].publicKey;
    xs = { iphone: info[0].xShare, server: info[1].xShare };
  } else {
    const k = await run(pair2p, (m, t, i) => m.ecKey2pDkg(t, i, pair2p, curve));
    const info = pair2p.map((n, i) => inst[n].ecKey2pInfo(k[i]));
    pubSec1 = info[0].publicKey;
    xs = { iphone: info[0].xShare, server: info[1].xShare };
  }
  const g1 = await reshare(curve, ALL, pubSec1, pair2p, xs, TWO_OF_THREE);
  check(Object.keys(g1).length === 3, "2P -> 2-of-3: every party got a blob");
  const pub = verifier.acKeyInfo(g1.mac).publicKey;
  check(ALL.every((n) => hex(verifier.acKeyInfo(g1[n]).publicKey) === hex(pub)), "same public key in every blob");
  if (curve === NID_secp256k1) {
    // ECDSA: signatures must verify against the original 2P key.
    const sigs = await run(["mac", "server"], (m, t, i) => m.signAc(t, i, ["mac", "server"], g1[["mac", "server"][i]], TWO_OF_THREE, hash, 0));
    check(verifier.verifyDer(curve, pubSec1, hash, sigs[0]), "mac+server signature verifies against the original 2P key");
  }
  await everyPairSigns(curve, "2P -> 2-of-3", g1, TWO_OF_THREE, pub);
  const g1r = await refreshAll(g1, TWO_OF_THREE);
  await everyPairSigns(curve, "after refreshAc", g1r, TWO_OF_THREE, pub);

  // 2. Lost iphone: mac + server reshare.
  const dealers = ["mac", "server"];
  const add: Keys = Object.fromEntries(dealers.map((n) => [n, inst[n].acToAdditiveShare(g1r[n], TWO_OF_THREE, dealers)]));
  const g2 = await reshare(curve, ALL, pub, dealers, add, TWO_OF_THREE);
  check(Object.keys(g2).length === 3, "lost device: new generation for all 3");
  await everyPairSigns(curve, "lost device", g2, TWO_OF_THREE, pub);
  check(!(await pairSigns(curve, pair2p, { iphone: g1r.iphone, server: g2.server }, TWO_OF_THREE, pub)),
    "old iphone share + new server share does not sign");

  // 3. 2-of-3 -> 2-of-2.
  const twoOfTwo = thresholdOf(2, pair2p);
  const add2: Keys = Object.fromEntries(pair2p.map((n) => [n, inst[n].acToAdditiveShare(g2[n], TWO_OF_THREE, pair2p)]));
  const g3 = await reshare(curve, pair2p, pub, pair2p, add2, twoOfTwo);
  check(await pairSigns(curve, pair2p, g3, twoOfTwo, pub), "2-of-3 -> 2-of-2: iphone+server signs");

  // 4. Rejections.
  const otherPub = verifier.acKeyInfo((await run(ALL, (m, t, i) => m.dkgAc(t, i, ALL, curve, TWO_OF_THREE, ALL)))[0]).publicKey;
  check(await rejects(reshare(curve, ALL, otherPub, dealers, add, TWO_OF_THREE)), "wrong public key rejected");
  check(!(await pairSigns(curve, pair2p, { iphone: g2.mac, server: g2.server }, TWO_OF_THREE, pub)),
    "mac blob presented as iphone does not sign");
}

console.log(`\n${passed}/${passed + failed} checks passed`);
process.exit(failed || passed === 0 ? 1 : 0);
