// One 2P party on native cb-mpc (bun:ffi) for bench/ts-bench.ts ffi. Runs the same op sequence as
// its peer worker. Timing is done by the main thread, as for the other backends: before run k the
// worker waits until ctrl[0] >= k (both parties start together), and after it adds 1 to ctrl[1]
// (the run ends when both have finished), so no party can start the next run's work early.
declare var self: Worker;
import { initCbMpcBunFfi, NID_secp256k1, NID_ED25519 } from "cb-mpc";
import { ringRead, ringWrite } from "./ring";

const NAMES: [string, string] = ["client", "server"];

self.onmessage = async (e: MessageEvent) => {
  const { party, inbox, outbox, ctrl: ctrlSab, nDkg, nSign } = e.data as {
    party: number; inbox: SharedArrayBuffer; outbox: SharedArrayBuffer; ctrl: SharedArrayBuffer; nDkg: number; nSign: number;
  };
  const ctrl = new Int32Array(ctrlSab);
  let k = 0;
  /** One barrier-framed run: wait for the start signal of run k, run, report done. */
  const run = async <T>(f: () => Promise<T>): Promise<T> => {
    k++;
    while (Atomics.load(ctrl, 0) < k) Atomics.wait(ctrl, 0, Atomics.load(ctrl, 0), 1000);
    const r = await f();
    Atomics.add(ctrl, 1, 1);
    Atomics.notify(ctrl, 1);
    return r;
  };
  try {
    const mpc = await initCbMpcBunFfi();
    const sendSync = (_to: number, m: Uint8Array) => (ringWrite(outbox, m), 0);
    const receiveSync = () => ringRead(inbox);
    const t: any = {
      sendSync, receiveSync,
      receiveAllSync: (ss: number[]) => ss.map(() => ringRead(inbox)),
      send: async (to: number, m: Uint8Array) => sendSync(to, m),
      receive: async () => receiveSync(),
      receiveAll: async (ss: number[]) => ss.map(() => ringRead(inbox)),
    };
    self.postMessage({ type: "ready" });
    let key: any;
    for (let i = 0; i < nDkg; i++) key = await run(() => mpc.ecdsa2pDkg(t, party, NAMES, NID_secp256k1));
    for (const batch of [1, 10]) {
      for (let i = 0; i < nSign; i++) {
        // distinct digests below the curve order (cb-mpc rejects a message >= q): byte 0 is 0x01
        const hashes = Array.from({ length: batch }, (_, j) => { const h = new Uint8Array(32).fill((i * 31 + j) & 255); h[0] = 1; return h; });
        const sid = new Uint8Array(32).fill(i & 255);
        await run(() => mpc.ecdsa2pSign(t, party, NAMES, key, sid, hashes));
      }
    }
    let ed: any;
    for (let i = 0; i < nDkg; i++) ed = await run(() => mpc.ecKey2pDkg(t, party, NAMES, NID_ED25519));
    for (let i = 0; i < nSign; i++) {
      const msg = new Uint8Array(32).fill(i & 255);
      await run(() => mpc.schnorr2pEddsaSign(t, party, NAMES, ed, msg));
    }
    self.postMessage({ type: "done" });
  } catch (err) {
    self.postMessage({ type: "error", message: err instanceof Error ? err.message : String(err) });
  }
};
