// Upgrade path for existing users: 2-of-2 key shares made by an older release
// (e.g. cb-mpc 0.1.9 on npm) are loaded by this build and reshared to 2-of-3
// (iphone, mac, server) keeping the public key; every pair then signs and the
// signatures verify against the ORIGINAL public key. Covers ECDSA-2P keys
// refreshed by the old release (P1's share is then unreduced mod q) and EdDSA-2P.
//
// Usage (from cb-mpc-ts/, after `npm i cb-mpc@0.1.9` in some dir):
//   bun run scripts/compat-reshare.ts <old>/node_modules/cb-mpc/dist/index.js

import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { resolve } from "node:path";

const OLD: any = await import(resolve(process.argv[2]));
const NEW: any = await import(resolve("dist/index.js"));
const ALL = ["iphone", "mac", "server"];
const PAIR = ["iphone", "server"]; // the existing 2-of-2 layout
const AC = NEW.thresholdOf(2, ALL);
const hash = new Uint8Array(createHash("sha256").update("compat-reshare").digest());
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

function mesh(n: number) {
  const qs = new Map<string, Uint8Array[]>(), ws = new Map<string, ((m: Uint8Array) => void)[]>();
  const put = (to: number, from: number, m: Uint8Array) => { const k = `${to}:${from}`, w = ws.get(k); if (w?.length) return w.shift()!(m); if (!qs.has(k)) qs.set(k, []); qs.get(k)!.push(m); };
  const take = (to: number, from: number) => { const k = `${to}:${from}`, q = qs.get(k); if (q?.length) return Promise.resolve(q.shift()!); return new Promise<Uint8Array>((r) => { if (!ws.has(k)) ws.set(k, []); ws.get(k)!.push(r); }); };
  return Array.from({ length: n }, (_, i) => ({
    async send(to: number, m: Uint8Array) { put(to, i, m.slice()); return 0; },
    async receive(f: number) { return take(i, f); },
    async receiveAll(fs: number[]) { return Promise.all(fs.map((f) => take(i, f))); },
  }));
}
async function run<T>(libs: any[], names: string[], fn: (m: any, t: any, i: number) => Promise<T>): Promise<T[]> {
  const t = mesh(names.length);
  return Promise.all(names.map((_, i) => fn(libs[i], t[i], i)));
}
const edVerify = (pub32: Uint8Array, sig: Uint8Array) =>
  nodeVerify(null, hash, createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub32]), format: "der", type: "spki" }), sig);
const edEncode = (sec1: Uint8Array) => { const p = new Uint8Array(32); for (let i = 0; i < 32; i++) p[i] = sec1[64 - i]; p[31] |= (sec1[32] & 1) << 7; return p; };

let pass = 0, fail = 0;
function check(ok: boolean, what: string) { console.log(`   ${ok ? "ok  " : "FAIL"} ${what}`); ok ? pass++ : fail++; }

const oldLibs = await Promise.all(PAIR.map(() => OLD.initCbMpc()));
const newLibs: Record<string, any> = {};
for (const n of ALL) newLibs[n] = await NEW.initCbMpc();
const libsFor = (names: string[]) => names.map((n) => newLibs[n]);

type Case = { label: string; curve: number; eddsa: boolean; refreshes: number };
const cases: Case[] = [
  { label: "ECDSA-2P secp256k1 from 0.1.9", curve: NEW.NID_secp256k1, eddsa: false, refreshes: 0 },
  { label: "ECDSA-2P secp256k1 from 0.1.9, refreshed 3x by 0.1.9", curve: NEW.NID_secp256k1, eddsa: false, refreshes: 3 },
  { label: "ECDSA-2P P-256 from 0.1.9, refreshed 1x by 0.1.9", curve: NEW.NID_X9_62_prime256v1, eddsa: false, refreshes: 1 },
  { label: "EdDSA-2P Ed25519 from 0.1.9", curve: NEW.NID_ED25519, eddsa: true, refreshes: 0 },
];

for (const c of cases) {
  console.log(`\n== ${c.label}`);
  // 1. Old release makes (and refreshes) the 2-of-2 key; shares are serialized as an app would store them.
  let k: any[] = await run(oldLibs, PAIR, (m, t, i) => (c.eddsa ? m.ecKey2pDkg(t, i, PAIR, c.curve) : m.ecdsa2pDkg(t, i, PAIR, c.curve)));
  for (let r = 0; r < c.refreshes; r++) k = await run(oldLibs, PAIR, (m, t, i) => m.ecdsa2pRefresh(t, i, PAIR, k[i]));
  const stored = k.map((key, i) => (c.eddsa ? oldLibs[i].serializeEcKey2p(key) : oldLibs[i].serializeEcdsa2p(key)));

  // 2. New build loads the stored shares.
  const loaded = PAIR.map((n, i) => (c.eddsa ? newLibs[n].deserializeEcKey2p(stored[i]) : newLibs[n].deserializeEcdsa2p(stored[i])));
  const info = PAIR.map((n, i) => (c.eddsa ? newLibs[n].ecKey2pInfo(loaded[i]) : newLibs[n].ecdsa2pKeyInfo(loaded[i])));
  const pub2p: Uint8Array = info[0].publicKey;
  if (!c.eddsa) console.log(`   (P1 share ${info[0].xShare.length} bytes, P2 share ${info[1].xShare.length} bytes)`);

  // 3. Reshare 2-of-2 -> 2-of-3 with the same public key; the 2P parties are the dealers.
  const xs: Record<string, Uint8Array> = { iphone: info[0].xShare, server: info[1].xShare };
  let blobs: Record<string, Uint8Array> = {};
  try {
    const out = await run(libsFor(ALL), ALL, (m, t, i) =>
      m.reshareFromAdditive(t, i, ALL, c.curve, pub2p, PAIR, xs[ALL[i]] ?? null, AC));
    ALL.forEach((n, i) => out[i].length && (blobs[n] = out[i]));
    check(Object.keys(blobs).length === 3, "reshare 2-of-2 -> 2-of-3: every party got a blob");
  } catch (e) {
    check(false, `reshare failed: ${(e as Error).message}`);
    continue;
  }
  const acPub: Uint8Array = newLibs.mac.acKeyInfo(blobs.mac).publicKey;
  const origCompressed = c.eddsa ? edEncode(pub2p) : (() => { const o = new Uint8Array(33); o[0] = 0x02 | (pub2p[64] & 1); o.set(pub2p.slice(1, 33), 1); return o; })();
  check(hex(acPub) === hex(origCompressed), "2-of-3 public key == original 2-of-2 public key");

  // 4. Every pair signs; signatures verify against the ORIGINAL key.
  for (const pair of [["iphone", "mac"], ["iphone", "server"], ["mac", "server"]]) {
    const sigs = await run(libsFor(pair), pair, (m, t, i) => m.signAc(t, i, pair, blobs[pair[i]], AC, hash, 0));
    const ok = c.eddsa ? edVerify(origCompressed, sigs[0]) : newLibs.mac.verifyDer(c.curve, pub2p, hash, sigs[0]);
    check(ok, `${pair.join("+")} signs, verifies against the original key`);
  }

  // 5. Lost iphone: mac + server reshare a new generation; still the original key.
  const dealers = ["mac", "server"];
  const add: Record<string, Uint8Array> = Object.fromEntries(dealers.map((n) => [n, newLibs[n].acToAdditiveShare(blobs[n], AC, dealers)]));
  const out2 = await run(libsFor(ALL), ALL, (m, t, i) => m.reshareFromAdditive(t, i, ALL, c.curve, acPub, dealers, add[ALL[i]] ?? null, AC));
  const g2: Record<string, Uint8Array> = {};
  ALL.forEach((n, i) => out2[i].length && (g2[n] = out2[i]));
  const sigs2 = await run(libsFor(["iphone", "server"]), ["iphone", "server"], (m, t, i) =>
    m.signAc(t, i, ["iphone", "server"], g2[["iphone", "server"][i]], AC, hash, 0));
  check(c.eddsa ? edVerify(origCompressed, sigs2[0]) : newLibs.mac.verifyDer(c.curve, pub2p, hash, sigs2[0]),
    "after lost-device reshare: new iphone + server sign with the original key");

  // 6. The old 2-of-2 shares still sign on the new build (nothing was consumed).
  const s2p: any[] = await run(libsFor(PAIR), PAIR, (m, t, i) =>
    c.eddsa ? m.schnorr2pEddsaSign(t, i, PAIR, loaded[i], hash) : m.ecdsa2pSign(t, i, PAIR, loaded[i], new Uint8Array(0), [hash]));
  check(c.eddsa ? edVerify(origCompressed, s2p[0]) : newLibs.mac.verifyDer(c.curve, pub2p, hash, s2p[0][0]),
    "the original 2-of-2 shares still sign");
}

console.log(`\n${pass}/${pass + fail} checks passed`);
process.exit(fail ? 1 : 0);
