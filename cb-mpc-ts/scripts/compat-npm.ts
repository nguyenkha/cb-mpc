// Compatibility test: a published cb-mpc release (npm) vs this build.
//
// 1. Key compat:  keys made + serialized by one version are deserialized and
//                 used (sign + verify) by the other version.
// 2. Wire compat: one party runs the old library, the other the new one.
//
// Usage (from cb-mpc-ts/, after npm i cb-mpc@<old> in some dir):
//   bun run scripts/compat-npm.ts <old>/node_modules/cb-mpc/dist/index.js ./dist/index.js \
//     [prebuilds/<platform>/libcbmpc.(dylib|so)]

import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";

const [oldPath, newPath, newNativeLib] = process.argv.slice(2);
const OLD: any = await import(oldPath);
const NEW: any = await import(newPath);
const { NID_secp256k1, NID_X9_62_prime256v1, NID_ED25519 } = NEW;

// ---- mock network (same as examples/mock-transport.ts) ----
function createMockNetwork(n: number) {
  const nets: any[] = [];
  for (let i = 0; i < n; i++) {
    const queues = new Map<number, Uint8Array[]>();
    const waiters = new Map<number, ((m: Uint8Array) => void)[]>();
    nets.push({
      enqueue(sender: number, data: Uint8Array) {
        const w = waiters.get(sender);
        if (w && w.length) return w.shift()!(data);
        if (!queues.has(sender)) queues.set(sender, []);
        queues.get(sender)!.push(data);
      },
      async send(receiver: number, msg: Uint8Array) {
        nets[receiver].enqueue(i, msg.slice());
        return 0;
      },
      async receive(sender: number) {
        const q = queues.get(sender);
        if (q && q.length) return q.shift()!;
        return new Promise<Uint8Array>((res) => {
          if (!waiters.has(sender)) waiters.set(sender, []);
          waiters.get(sender)!.push(res);
        });
      },
      async receiveAll(senders: number[]) {
        return Promise.all(senders.map((s) => this.receive(s)));
      },
    });
  }
  return nets;
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const sha256 = (s: string) => new Uint8Array(createHash("sha256").update(s).digest());

function ed25519Verify(sec1: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  const x = sec1.slice(1, 33), y = sec1.slice(33, 65);
  const pub = new Uint8Array(32);
  for (let i = 0; i < 32; i++) pub[i] = y[31 - i];
  pub[31] |= (x[31] & 1) << 7;
  const key = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub]),
    format: "der",
    type: "spki",
  });
  return nodeVerify(null, msg, key, sig);
}

// Fail fast if a protocol hangs (e.g. wire-incompatible message flow).
function withTimeout<T>(p: Promise<T>, ms = 60000): Promise<T> {
  return Promise.race([p, new Promise<T>((_, rej) => setTimeout(() => rej(new Error(`timeout ${ms}ms`)), ms))]);
}

const results: { name: string; ok: boolean; note?: string }[] = [];
async function check(name: string, fn: () => Promise<string | void>) {
  const t = Date.now();
  try {
    const note = await fn();
    results.push({ name, ok: true, note: note || undefined });
    console.log(`PASS ${name} (${Date.now() - t} ms)${note ? " - " + note : ""}`);
  } catch (e) {
    results.push({ name, ok: false, note: (e as Error).message });
    console.log(`FAIL ${name}: ${(e as Error).message}`);
  }
}

const libs: Record<string, any> = { old: OLD, new: NEW };
const inst = (v: string) => libs[v].initCbMpc();
const P2 = ["p0", "p1"] as [string, string];
const PM = ["p0", "p1", "p2"];

// ---------------- helpers per protocol ----------------

async function ecdsa2pDkg(a: any, b: any, curve: number) {
  const [t0, t1] = createMockNetwork(2);
  return withTimeout(Promise.all([a.ecdsa2pDkg(t0, 0, P2, curve), b.ecdsa2pDkg(t1, 1, P2, curve)]));
}
async function ecdsa2pSign(a: any, b: any, k0: any, k1: any, h: Uint8Array) {
  const [t0, t1] = createMockNetwork(2);
  const sid = new Uint8Array(0);
  const [s0] = await withTimeout(
    Promise.all([a.ecdsa2pSign(t0, 0, P2, k0, sid, [h]), b.ecdsa2pSign(t1, 1, P2, k1, sid, [h])]),
  );
  return s0[0] as Uint8Array;
}
async function ecdsa2pRefresh(a: any, b: any, k0: any, k1: any) {
  const [t0, t1] = createMockNetwork(2);
  return withTimeout(Promise.all([a.ecdsa2pRefresh(t0, 0, P2, k0), b.ecdsa2pRefresh(t1, 1, P2, k1)]));
}
async function ecKey2pDkg(a: any, b: any) {
  const [t0, t1] = createMockNetwork(2);
  return withTimeout(Promise.all([a.ecKey2pDkg(t0, 0, P2, NID_ED25519), b.ecKey2pDkg(t1, 1, P2, NID_ED25519)]));
}
async function eddsa2pSign(a: any, b: any, k0: any, k1: any, m: Uint8Array) {
  const [t0, t1] = createMockNetwork(2);
  const [s0] = await withTimeout(
    Promise.all([a.schnorr2pEddsaSign(t0, 0, P2, k0, m), b.schnorr2pEddsaSign(t1, 1, P2, k1, m)]),
  );
  return s0 as Uint8Array;
}
async function ecKeyMpDkg(ms: any[], curveCode: number) {
  const nets = createMockNetwork(3);
  const curves = ms.map((m) => m.createCurve(curveCode));
  const keys = await withTimeout(Promise.all(ms.map((m, i) => m.ecKeyMpDkg(nets[i], 3, i, PM, curves[i]))));
  ms.forEach((m, i) => m.freeCurve(curves[i]));
  return keys;
}
async function mpSign(kind: "ecdsa" | "eddsa", ms: any[], keys: any[], m: Uint8Array) {
  const nets = createMockNetwork(3);
  const fn = kind === "ecdsa" ? "ecdsaMpSign" : "eddsaMpSign";
  const sigs = await withTimeout(Promise.all(ms.map((x, i) => x[fn](nets[i], 3, i, PM, keys[i], m, 0))));
  return sigs[0] as Uint8Array;
}

// ---------------- 1. key compat ----------------

async function keyCompat(from: string, to: string) {
  const tag = `key ${from}->${to}`;

  await check(`${tag}: ECDSA-2P secp256k1 (load, sign, refresh, sign)`, async () => {
    const [a, b] = [await inst(from), await inst(from)];
    const [k0, k1] = await ecdsa2pDkg(a, b, NID_secp256k1);
    const s0 = a.serializeEcdsa2p(k0), s1 = b.serializeEcdsa2p(k1);
    const pub = a.ecdsa2pKeyInfo(k0).publicKey;

    const [c, d] = [await inst(to), await inst(to)];
    const r0 = c.deserializeEcdsa2p(s0), r1 = d.deserializeEcdsa2p(s1);
    const i0 = c.ecdsa2pKeyInfo(r0);
    if (hex(i0.publicKey) !== hex(pub)) throw new Error("public key changed");
    if (hex(i0.xShare) !== hex(a.ecdsa2pKeyInfo(k0).xShare)) throw new Error("x share changed");
    // re-serializing must give identical bytes
    if (c.serializeEcdsa2p(r0).map(hex).join() !== s0.map(hex).join()) throw new Error("re-serialize differs");

    const h = sha256("key compat " + tag);
    const sig = await ecdsa2pSign(c, d, r0, r1, h);
    if (!c.verifyDer(NID_secp256k1, pub, h, sig)) throw new Error("sig invalid (to lib)");
    if (!a.verifyDer(NID_secp256k1, pub, h, sig)) throw new Error("sig invalid (from lib)");

    const [n0, n1] = await ecdsa2pRefresh(c, d, r0, r1);
    const sig2 = await ecdsa2pSign(c, d, n0, n1, h);
    if (!c.verifyDer(NID_secp256k1, pub, h, sig2)) throw new Error("sig after refresh invalid");
  });

  await check(`${tag}: ECDSA-2P P-256 (load, sign)`, async () => {
    const [a, b] = [await inst(from), await inst(from)];
    const [k0, k1] = await ecdsa2pDkg(a, b, NID_X9_62_prime256v1);
    const s0 = a.serializeEcdsa2p(k0), s1 = b.serializeEcdsa2p(k1);
    const pub = a.ecdsa2pKeyInfo(k0).publicKey;
    const [c, d] = [await inst(to), await inst(to)];
    const r0 = c.deserializeEcdsa2p(s0), r1 = d.deserializeEcdsa2p(s1);
    const h = sha256("p256");
    const sig = await ecdsa2pSign(c, d, r0, r1, h);
    if (!c.verifyDer(NID_X9_62_prime256v1, pub, h, sig)) throw new Error("sig invalid");
  });

  await check(`${tag}: EdDSA-2P (load, sign)`, async () => {
    const [a, b] = [await inst(from), await inst(from)];
    const [k0, k1] = await ecKey2pDkg(a, b);
    const s0 = a.serializeEcKey2p(k0), s1 = b.serializeEcKey2p(k1);
    const pub = a.ecKey2pInfo(k0).publicKey;
    const [c, d] = [await inst(to), await inst(to)];
    const r0 = c.deserializeEcKey2p(s0), r1 = d.deserializeEcKey2p(s1);
    if (hex(c.ecKey2pInfo(r0).publicKey) !== hex(pub)) throw new Error("public key changed");
    const m = new TextEncoder().encode("eddsa 2p " + tag);
    const sig = await eddsa2pSign(c, d, r0, r1, m);
    if (!ed25519Verify(pub, m, sig)) throw new Error("ed25519 sig invalid");
  });

  await check(`${tag}: ECDSA-MP 3-party secp256k1 (load, sign)`, async () => {
    const A = [await inst(from), await inst(from), await inst(from)];
    const keys = await ecKeyMpDkg(A, NID_secp256k1);
    const sers = keys.map((k: any, i: number) => A[i].serializeEcKeyMp(k));
    const pub = A[0].ecKeyMpInfo(keys[0]).publicKey;
    const B = [await inst(to), await inst(to), await inst(to)];
    const rs = sers.map((s: any, i: number) => B[i].deserializeEcKeyMp(s));
    if (hex(B[0].ecKeyMpInfo(rs[0]).publicKey) !== hex(pub)) throw new Error("public key changed");
    const h = sha256("ecdsa mp");
    const sig = await mpSign("ecdsa", B, rs, h);
    if (!B[0].verifyDer(NID_secp256k1, pub, h, sig)) throw new Error("sig invalid");
  });

  await check(`${tag}: EdDSA-MP 3-party (load, sign)`, async () => {
    const A = [await inst(from), await inst(from), await inst(from)];
    const keys = await ecKeyMpDkg(A, NID_ED25519);
    const sers = keys.map((k: any, i: number) => A[i].serializeEcKeyMp(k));
    const pub = A[0].ecKeyMpInfo(keys[0]).publicKey;
    const B = [await inst(to), await inst(to), await inst(to)];
    const rs = sers.map((s: any, i: number) => B[i].deserializeEcKeyMp(s));
    const m = new TextEncoder().encode("eddsa mp");
    const sig = await mpSign("eddsa", B, rs, m);
    if (!ed25519Verify(pub, m, sig)) throw new Error("ed25519 sig invalid");
  });
}

// ---------------- 2. wire compat (old party <-> new party) ----------------

async function wireCompat() {
  await check("wire: ECDSA-2P DKG old(p0) + new(p1)", async () => {
    const [a, b] = [await inst("old"), await inst("new")];
    const [k0, k1] = await ecdsa2pDkg(a, b, NID_secp256k1);
    const h = sha256("wire");
    const sig = await ecdsa2pSign(a, b, k0, k1, h);
    if (!a.verifyDer(NID_secp256k1, a.ecdsa2pKeyInfo(k0).publicKey, h, sig)) throw new Error("sig invalid");
  });
  await check("wire: ECDSA-2P sign new(p0) + old(p1) on shared key", async () => {
    const [a, b] = [await inst("new"), await inst("new")];
    const [k0, k1] = await ecdsa2pDkg(a, b, NID_secp256k1);
    const o = await inst("old");
    const k1old = o.deserializeEcdsa2p(b.serializeEcdsa2p(k1));
    const h = sha256("wire2");
    const sig = await ecdsa2pSign(a, o, k0, k1old, h);
    if (!a.verifyDer(NID_secp256k1, a.ecdsa2pKeyInfo(k0).publicKey, h, sig)) throw new Error("sig invalid");
  });
  await check("wire: EdDSA-2P DKG+sign old(p0) + new(p1)", async () => {
    const [a, b] = [await inst("old"), await inst("new")];
    const [k0, k1] = await ecKey2pDkg(a, b);
    const m = new TextEncoder().encode("wire eddsa");
    const sig = await eddsa2pSign(a, b, k0, k1, m);
    if (!ed25519Verify(a.ecKey2pInfo(k0).publicKey, m, sig)) throw new Error("sig invalid");
  });
  await check("wire: EC-key MP DKG + ECDSA-MP sign old,new,new", async () => {
    const ms = [await inst("old"), await inst("new"), await inst("new")];
    const keys = await ecKeyMpDkg(ms, NID_secp256k1);
    const h = sha256("wire mp");
    const sig = await mpSign("ecdsa", ms, keys, h);
    if (!ms[0].verifyDer(NID_secp256k1, ms[0].ecKeyMpInfo(keys[0]).publicKey, h, sig)) throw new Error("sig invalid");
  });
  await check("wire: agreeRandom old(p0) + new(p1)", async () => {
    const [a, b] = [await inst("old"), await inst("new")];
    const [t0, t1] = createMockNetwork(2);
    const [r0, r1] = await withTimeout(Promise.all([a.agreeRandom(t0, 0, P2, 256), b.agreeRandom(t1, 1, P2, 256)]));
    if (hex(r0) !== hex(r1)) throw new Error("outputs differ");
  });
}

// ---------------- 3. native backend: load old keys ----------------

async function nativeLoad() {
  if (!newNativeLib) return;
  await check("native new: load 0.1.9 keys (ECDSA-2P, EdDSA-2P, EC-key MP)", async () => {
    const [a, b] = [await inst("old"), await inst("old")];
    const [k0] = await ecdsa2pDkg(a, b, NID_secp256k1);
    const [e0] = await ecKey2pDkg(a, b);
    const A = [await inst("old"), await inst("old"), await inst("old")];
    const mk = await ecKeyMpDkg(A, NID_secp256k1);

    const n = await NEW.initCbMpcBunFfi(newNativeLib);
    const r = n.deserializeEcdsa2p(a.serializeEcdsa2p(k0));
    if (hex(n.ecdsa2pKeyInfo(r).publicKey) !== hex(a.ecdsa2pKeyInfo(k0).publicKey)) throw new Error("ecdsa2p pub");
    const re = n.deserializeEcKey2p(a.serializeEcKey2p(e0));
    if (hex(n.ecKey2pInfo(re).xShare) !== hex(a.ecKey2pInfo(e0).xShare)) throw new Error("eckey2p share");
    const rm = n.deserializeEcKeyMp(A[0].serializeEcKeyMp(mk[0]));
    if (hex(n.ecKeyMpInfo(rm).publicKey) !== hex(A[0].ecKeyMpInfo(mk[0]).publicKey)) throw new Error("eckeymp pub");
  });
}

await keyCompat("old", "new");
await keyCompat("new", "old");
await wireCompat();
await nativeLoad();

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);
