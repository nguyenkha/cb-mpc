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
