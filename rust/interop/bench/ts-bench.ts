// Benchmark of the released cb-mpc-ts (npm, rust/interop/package.json) with both 2P parties in this
// process, same ops and output as rust/cbmpc/examples/bench.rs:
//   bun bench/ts-bench.ts wasm [runs_dkg] [runs_sign]   both parties on WASM, in-memory async transport
//   bun bench/ts-bench.ts ffi  [runs_dkg] [runs_sign]   both parties on native cb-mpc via bun:ffi, one
//                                                       Worker each (native calls block in receive),
//                                                       messages over SharedArrayBuffer rings
// Prints one JSON line per op ({backend, op, runs, median_ms, p95_ms}) and one with peak RSS.
import { initCbMpc, NID_secp256k1, NID_ED25519, type DataTransport } from "cb-mpc";
import { cpus } from "os";
import { createRing } from "./ring";

const NAMES: [string, string] = ["client", "server"];
const [backend = "wasm", nDkgArg, nSignArg] = process.argv.slice(2);
const nDkg = Number(nDkgArg ?? 10);
const nSign = Number(nSignArg ?? 30);

function report(op: string, ms: number[]) {
  ms.sort((a, b) => a - b);
  const pick = (q: number) => ms[Math.round((ms.length - 1) * q)];
  console.log(JSON.stringify({ backend, op, runs: ms.length, median_ms: +pick(0.5).toFixed(2), p95_ms: +pick(0.95).toFixed(2) }));
}

function memoryPair(): [DataTransport, DataTransport] {
  const q: Uint8Array[][] = [[], []];
  const waiting: (((m: Uint8Array) => void) | null)[] = [null, null];
  const take = (me: number) => new Promise<Uint8Array>((r) => { const m = q[me].shift(); if (m) r(m); else waiting[me] = r; });
  const t = (me: number): DataTransport => ({
    async send(to, m) { const w = waiting[to]; if (w) { waiting[to] = null; w(new Uint8Array(m)); } else q[to].push(new Uint8Array(m)); return 0; },
    receive: () => take(me),
    receiveAll: (ss) => Promise.all(ss.map(() => take(me))),
  });
  return [t(0), t(1)];
}

async function benchWasm() {
  const [a, b] = [await initCbMpc(), await initCbMpc()];
  const times: Record<string, number[]> = {};
  const time = async (op: string, f: () => Promise<unknown>) => {
    const s = performance.now();
    const r = await f();
    (times[op] ??= []).push(performance.now() - s);
    return r;
  };
  let keys: any[] = [];
  for (let i = 0; i < nDkg; i++) {
    const [ta, tb] = memoryPair();
    keys = (await time("ecdsa_dkg", () => Promise.all([a.ecdsa2pDkg(ta, 0, NAMES, NID_secp256k1), b.ecdsa2pDkg(tb, 1, NAMES, NID_secp256k1)]))) as any[];
  }
  for (const batch of [1, 10]) {
    for (let i = 0; i < nSign; i++) {
      // distinct digests below the curve order (cb-mpc rejects a message >= q): byte 0 is 0x01
        const hashes = Array.from({ length: batch }, (_, j) => { const h = new Uint8Array(32).fill((i * 31 + j) & 255); h[0] = 1; return h; });
      const sid = new Uint8Array(32).fill(i & 255);
      const [ta, tb] = memoryPair();
      await time(`ecdsa_sign_${batch}`, () => Promise.all([a.ecdsa2pSign(ta, 0, NAMES, keys[0], sid, hashes), b.ecdsa2pSign(tb, 1, NAMES, keys[1], sid, hashes)]));
    }
  }
  let ed: any[] = [];
  for (let i = 0; i < nDkg; i++) {
    const [ta, tb] = memoryPair();
    ed = (await time("eddsa_dkg", () => Promise.all([a.ecKey2pDkg(ta, 0, NAMES, NID_ED25519), b.ecKey2pDkg(tb, 1, NAMES, NID_ED25519)]))) as any[];
  }
  for (let i = 0; i < nSign; i++) {
    const msg = new Uint8Array(32).fill(i & 255);
    const [ta, tb] = memoryPair();
    await time("eddsa_sign", () => Promise.all([a.schnorr2pEddsaSign(ta, 0, NAMES, ed[0], msg), b.schnorr2pEddsaSign(tb, 1, NAMES, ed[1], msg)]));
  }
  return times;
}

async function benchFfi() {
  // ring[i] carries messages TO party i.
  const rings = [createRing(), createRing()];
  const url = new URL("./ffi-party-worker.ts", import.meta.url).href;
  // ctrl[0] = index of the run both workers may start, ctrl[1] = finished party-runs (see the worker).
  const ctrlSab = new SharedArrayBuffer(8);
  const ctrl = new Int32Array(ctrlSab);
  const workers = [new Worker(url), new Worker(url)];
  const state = workers.map((w) => {
    const s = { ready: null as null | Promise<void>, done: null as null | Promise<void> };
    let ready!: () => void, done!: () => void, fail!: (e: Error) => void;
    s.ready = new Promise<void>((r, j) => { ready = r; fail = j; });
    s.done = new Promise<void>((r, j) => { done = r; const f = fail; fail = (e) => { f(e); j(e); }; });
    w.onmessage = (e) => (e.data.type === "ready" ? ready() : e.data.type === "done" ? done() : fail(new Error(e.data.message)));
    w.onerror = (e) => fail(new Error(e.message));
    return s;
  });
  workers.forEach((w, party) => w.postMessage({ party, inbox: rings[party], outbox: rings[1 - party], ctrl: ctrlSab, nDkg, nSign }));
  await Promise.all(state.map((s) => s.ready)); // native library loaded in both

  // The main thread times every run from the common start signal until both parties are done.
  const times: Record<string, number[]> = {};
  const plan: [string, number][] = [["ecdsa_dkg", nDkg], ["ecdsa_sign_1", nSign], ["ecdsa_sign_10", nSign], ["eddsa_dkg", nDkg], ["eddsa_sign", nSign]];
  let k = 0;
  for (const [op, n] of plan) {
    for (let i = 0; i < n; i++) {
      k++;
      const start = performance.now();
      Atomics.store(ctrl, 0, k);
      Atomics.notify(ctrl, 0);
      while (Atomics.load(ctrl, 1) < 2 * k) {
        if (performance.now() - start > 120_000) throw new Error(`ffi run ${op} #${i} did not finish`);
        Atomics.wait(ctrl, 1, Atomics.load(ctrl, 1), 1000);
      }
      (times[op] ??= []).push(performance.now() - start);
    }
  }
  await Promise.all(state.map((s) => s.done));
  workers.forEach((w) => w.terminate());
  return times;
}

const times = backend === "ffi" ? await benchFfi() : await benchWasm();
for (const op of ["ecdsa_dkg", "ecdsa_sign_1", "ecdsa_sign_10", "eddsa_dkg", "eddsa_sign"]) report(op, times[op]);
// Peak RSS of the whole process (worker threads included). Bun reports maxRSS like getrusage:
// bytes on macOS, KiB on Linux.
const rss = process.resourceUsage().maxRSS / (process.platform === "darwin" ? 1048576 : 1024);
console.log(JSON.stringify({ backend, peak_rss_mb: +rss.toFixed(1), cpus: cpus().length }));
process.exit(0);
