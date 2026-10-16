// One 2P party on native cb-mpc (bun:ffi) for bench/ts-bench.ts ffi. Runs the same op sequence as
// its peer worker; the protocol messages keep the two in lockstep. Posts its per-run times.
declare var self: Worker;
import { initCbMpcBunFfi, NID_secp256k1, NID_ED25519 } from "cb-mpc";
import { ringRead, ringWrite } from "./ring";

const NAMES: [string, string] = ["client", "server"];

self.onmessage = async (e: MessageEvent) => {
  const { party, inbox, outbox, nDkg, nSign } = e.data as {
    party: number; inbox: SharedArrayBuffer; outbox: SharedArrayBuffer; nDkg: number; nSign: number;
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
    const times: Record<string, number[]> = {};
    const time = async <T>(op: string, f: () => Promise<T>): Promise<T> => {
      const s = performance.now();
      const r = await f();
      (times[op] ??= []).push(performance.now() - s);
      return r;
    };
    let key: any;
    for (let i = 0; i < nDkg; i++) key = await time("ecdsa_dkg", () => mpc.ecdsa2pDkg(t, party, NAMES, NID_secp256k1));
    for (const batch of [1, 10]) {
      for (let i = 0; i < nSign; i++) {
        // distinct digests below the curve order (cb-mpc rejects a message >= q): byte 0 is 0x01
        const hashes = Array.from({ length: batch }, (_, j) => { const h = new Uint8Array(32).fill((i * 31 + j) & 255); h[0] = 1; return h; });
        const sid = new Uint8Array(32).fill(i & 255);
        await time(`ecdsa_sign_${batch}`, () => mpc.ecdsa2pSign(t, party, NAMES, key, sid, hashes));
      }
    }
    let ed: any;
    for (let i = 0; i < nDkg; i++) ed = await time("eddsa_dkg", () => mpc.ecKey2pDkg(t, party, NAMES, NID_ED25519));
    for (let i = 0; i < nSign; i++) {
      const msg = new Uint8Array(32).fill(i & 255);
      await time("eddsa_sign", () => mpc.schnorr2pEddsaSign(t, party, NAMES, ed, msg));
    }
    self.postMessage({ type: "done", times });
  } catch (err) {
    self.postMessage({ type: "error", message: err instanceof Error ? err.message : String(err) });
  }
};
