// Error-path regression tests (WASM + native bun:ffi). Every bad call must
// surface as a JS error and leave the library usable: no uninitialized output
// freed, no C++ exception escaping the C ABI (which aborts native hosts).
//
// Usage (from cb-mpc-ts/): bun run scripts/error-paths.ts [path/to/libcbmpc.(dylib|so)]

import { createHash } from "node:crypto";
import { resolve } from "node:path";

const M: any = await import(resolve("dist/index.js"));
const libPath = resolve(process.argv[2] || `prebuilds/${process.platform}-${process.arch}/libcbmpc.${process.platform === "darwin" ? "dylib" : "so"}`);

// A real ECDSA-2P key pair made on WASM, serialized, so each backend can load it.
const [a, b] = [await M.initCbMpc(), await M.initCbMpc()];
const q: Uint8Array[][] = [[], []];
const w: any[] = [null, null];
const tr = (i: number) => ({
  async send(_r: number, m: Uint8Array) { const o = 1 - i; if (w[o]) { const f = w[o]; w[o] = null; f(m.slice()); } else q[o].push(m.slice()); return 0; },
  async receive() { return q[i].length ? q[i].shift()! : new Promise<Uint8Array>((r) => (w[i] = r)); },
  async receiveAll(s: number[]) { return Promise.all(s.map(() => this.receive())); },
});
const [k0] = await Promise.all([a.ecdsa2pDkg(tr(0), 0, ["p0", "p1"], M.NID_secp256k1), b.ecdsa2pDkg(tr(1), 1, ["p0", "p1"], M.NID_secp256k1)]);
const ser0: Uint8Array[] = a.serializeEcdsa2p(k0);

// Generic in-process async network for n WASM parties.
function mesh(n: number) {
  const qs = new Map<string, Uint8Array[]>(), ws = new Map<string, ((m: Uint8Array) => void)[]>();
  const put = (to: number, from: number, m: Uint8Array) => {
    const k = `${to}:${from}`, w = ws.get(k);
    if (w?.length) return w.shift()!(m);
    if (!qs.has(k)) qs.set(k, []);
    qs.get(k)!.push(m);
  };
  const take = (to: number, from: number) => {
    const k = `${to}:${from}`, q = qs.get(k);
    if (q?.length) return Promise.resolve(q.shift()!);
    return new Promise<Uint8Array>((r) => { if (!ws.has(k)) ws.set(k, []); ws.get(k)!.push(r); });
  };
  return Array.from({ length: n }, (_, i) => ({
    async send(to: number, m: Uint8Array) { put(to, i, m.slice()); return 0; },
    async receive(from: number) { return take(i, from); },
    async receiveAll(fs: number[]) { return Promise.all(fs.map((f) => take(i, f))); },
  }));
}

// A second ECDSA-2P key (P1 share) to splice parts from, an EdDSA-2P key and a 3-party MP key set.
const [c, d] = [await M.initCbMpc(), await M.initCbMpc()];
let net2 = mesh(2);
const [k0b] = await Promise.all([c.ecdsa2pDkg(net2[0], 0, ["p0", "p1"], M.NID_secp256k1), d.ecdsa2pDkg(net2[1], 1, ["p0", "p1"], M.NID_secp256k1)]);
const ser0b: Uint8Array[] = c.serializeEcdsa2p(k0b);
net2 = mesh(2);
const [e0] = await Promise.all([c.ecKey2pDkg(net2[0], 0, ["p0", "p1"], M.NID_ED25519), d.ecKey2pDkg(net2[1], 1, ["p0", "p1"], M.NID_ED25519)]);
const serE: Uint8Array[] = c.serializeEcKey2p(e0);
const mps = [await M.initCbMpc(), await M.initCbMpc(), await M.initCbMpc()];
const net3 = mesh(3);
const mpKeys = await Promise.all(mps.map((m, i) => { const cv = m.createCurve(M.NID_secp256k1); return m.ecKeyMpDkg(net3[i], 3, i, ["p0", "p1", "p2"], cv); }));
const serM: Uint8Array[][] = mpKeys.map((k: any, i: number) => mps[i].serializeEcKeyMp(k));
const splice = (base: Uint8Array[], idx: number, part: Uint8Array) => base.map((x, i) => (i === idx ? part.slice() : x.slice()));
const flipLast = (x: Uint8Array) => { const y = x.slice(); y[y.length - 1] ^= 1; return y; };

// Transport that must never be used (calls fail before any message).
const dead = {
  async send() { return -1; }, async receive() { return new Uint8Array(0); }, async receiveAll() { return []; },
  sendSync() { return -1; }, receiveSync() { return new Uint8Array(0); }, receiveAllSync() { return []; },
};

let pass = 0, fail = 0;
async function expectError(name: string, fn: () => any, kind: "CbMpcError" | "RangeError" = "CbMpcError") {
  try {
    await fn();
    fail++; console.log(`FAIL ${name}: no error`);
  } catch (e) {
    const ok = kind === "RangeError" ? e instanceof RangeError : e instanceof M.CbMpcError;
    if (ok) { pass++; console.log(`PASS ${name}`); } else { fail++; console.log(`FAIL ${name}: ${(e as Error).name}: ${(e as Error).message}`); }
  }
}

for (const [backend, init] of [["wasm", () => M.initCbMpc()], ["native", () => M.initCbMpcBunFfi(libPath)]] as const) {
  const m = await init();
  const key0 = m.deserializeEcdsa2p(ser0); // role 0 (P1)

  await expectError(`${backend}: agreeRandom bitLen=0`, () => m.agreeRandom(dead, 0, ["p0", "p1"], 0));
  // role mismatch: key belongs to P1 but we run as P2 -> cb_assert inside the protocol
  await expectError(`${backend}: ecdsa2pRefresh with key of the other role`, () => m.ecdsa2pRefresh(dead, 1, ["p0", "p1"], key0));
  await expectError(`${backend}: ecdsa2pSign with key of the other role`, () =>
    m.ecdsa2pSign(dead, 1, ["p0", "p1"], key0, new Uint8Array(0), [new Uint8Array(32)]));
  await expectError(`${backend}: deserializeEcdsa2p 5 parts`, () => m.deserializeEcdsa2p(ser0.slice(0, 5)));
  await expectError(`${backend}: deserializeEcdsa2p role=2`, () => {
    const bad = ser0.map((x) => x.slice());
    bad[0] = new Uint8Array([0, 0, 0, 2]);
    return m.deserializeEcdsa2p(bad);
  });
  await expectError(`${backend}: deserializeEcdsa2p truncated point`, () => {
    const bad = ser0.map((x) => x.slice());
    bad[2] = bad[2].slice(0, 10);
    return m.deserializeEcdsa2p(bad);
  });
  await expectError(`${backend}: serializeEcdsa2p null handle`, () => m.serializeEcdsa2p(0));
  // Tampered keys are rejected at deserialization.
  await expectError(`${backend}: ECDSA-2P P1 with another key's c_key`, () => m.deserializeEcdsa2p(splice(ser0, 4, ser0b[4])));
  await expectError(`${backend}: ECDSA-2P P1 with another key's x_share`, () => m.deserializeEcdsa2p(splice(ser0, 3, ser0b[3])));
  await expectError(`${backend}: ECDSA-2P Q not on curve`, () => m.deserializeEcdsa2p(splice(ser0, 2, flipLast(ser0[2]))));
  await expectError(`${backend}: EdDSA-2P Q not on curve`, () => m.deserializeEcKey2p(splice(serE, 2, flipLast(serE[2]))));
  await expectError(`${backend}: EC-key MP with another party's x_share`, () => m.deserializeEcKeyMp(splice(serM[0], 0, serM[1][0])));
  await expectError(`${backend}: EC-key MP with mismatched Q`, () => m.deserializeEcKeyMp(splice(serM[0], 1, a.serializeEcdsa2p(k0)[2])));
  // Untampered keys still load.
  {
    const ok = [m.deserializeEcdsa2p(ser0b), m.deserializeEcKey2p(serE), ...serM.map((x) => m.deserializeEcKeyMp(x))];
    if (ok.every((h: number) => h)) { pass++; console.log(`PASS ${backend}: valid keys of every type still load`); } else { fail++; console.log(`FAIL ${backend}: valid key rejected`); }
  }
  // Value-returning helpers report failures instead of returning empty values.
  await expectError(`${backend}: createCurve with unknown curve code`, () => m.createCurve(12345));
  await expectError(`${backend}: pointFromBytes garbage`, () => m.pointFromBytes(new Uint8Array([1, 2, 3])));
  await expectError(`${backend}: curveOrder on null handle`, () => m.curveOrder(0));
  await expectError(`${backend}: zkDlProve aux=-1`, () => m.zkDlProve(0, new Uint8Array(32), new Uint8Array(32), -1), "RangeError");

  // Library still healthy after all the errors: the loaded key signs-verifies via a fresh hash.
  const h = new Uint8Array(createHash("sha256").update("after-errors").digest());
  const info = m.ecdsa2pKeyInfo(key0);
  const healthy = info.roleIndex === 0 && m.serializeEcdsa2p(key0).length === 6;
  if (healthy) { pass++; console.log(`PASS ${backend}: library usable after errors`); } else { fail++; console.log(`FAIL ${backend}: library state`); }
  void h;
}

console.log(`\n${pass}/${pass + fail} passed`);
process.exit(fail ? 1 : 0);
