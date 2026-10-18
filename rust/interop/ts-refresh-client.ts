// cb-mpc-ts client party (P1, "client") for the Rust refresh interop test (rust/cbmpc/tests/interop_ts.rs,
// rust_server_party_refreshes_with_cb_mpc_ts). Same frames as ts-client.ts. Per curve: DKG, refresh (timed),
// new + new sign, then old client + new server and new client + old server, which must both fail on this side
// (P1 verifies the proof / the signature). The package comes from CBMPC_TS_DIR (a local cb-mpc-ts build) or the
// installed "cb-mpc"; one without ecKey2pRefresh answers "skip".
import { ed25519 } from "@noble/curves/ed25519.js";
import { writeSync } from "fs";
import { resolve } from "path";

const pkg = process.env.CBMPC_TS_DIR ? resolve(process.env.CBMPC_TS_DIR, "dist/index.js") : "cb-mpc";
const { initCbMpc, NID_secp256k1, NID_ED25519 } = await import(pkg);
type DataTransport = { send(r: number, m: Uint8Array): Promise<number>; receive(s: number): Promise<Uint8Array>; receiveAll(s: number[]): Promise<Uint8Array[]> };

const NAMES: [string, string] = ["client", "server"];
const RUNS = Number(process.env.REFRESH_BENCH_RUNS ?? 3);
const reader = Bun.stdin.stream().getReader();
let buf = new Uint8Array(0);

async function readFrame(): Promise<{ tag: string; data: Uint8Array }> {
  while (buf.length < 5 || buf.length < 5 + new DataView(buf.buffer, buf.byteOffset).getUint32(1)) {
    const { value, done } = await reader.read();
    if (done) throw new Error("stdin closed");
    const next = new Uint8Array(buf.length + value.length);
    next.set(buf);
    next.set(value, buf.length);
    buf = next;
  }
  const len = new DataView(buf.buffer, buf.byteOffset).getUint32(1);
  const frame = { tag: String.fromCharCode(buf[0]), data: buf.slice(5, 5 + len) };
  buf = buf.slice(5 + len);
  return frame;
}

function writeFrame(tag: string, data: Uint8Array) {
  const head = new Uint8Array(5);
  head[0] = tag.charCodeAt(0);
  new DataView(head.buffer).setUint32(1, data.length);
  writeSync(1, head);
  writeSync(1, data);
}

async function expectFrame(tag: string): Promise<Uint8Array> {
  const f = await readFrame();
  if (f.tag !== tag) throw new Error(`expected frame ${tag}, got ${f.tag}`);
  return f.data;
}

const control = (data: Uint8Array) => writeFrame("C", data);
const text = (s: string) => control(new TextEncoder().encode(s));
const pipe: DataTransport = {
  async send(_r, m) { writeFrame("M", m); return 0; },
  receive: () => expectFrame("M"),
  receiveAll: (s) => Promise.all(s.map(() => expectFrame("M"))),
};
const assert = (ok: boolean, what: string) => { if (!ok) throw new Error(`check failed: ${what}`); };
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const ed25519Compressed = (oct: Uint8Array) => { const o = oct.slice(33, 65).reverse(); o[31] |= (oct[32] & 1) << 7; return o; };
const ms = (t0: number) => Math.round((performance.now() - t0) * 10) / 10;

const mpc = await initCbMpc();
if (typeof mpc.ecKey2pRefresh !== "function") { text("skip"); process.exit(0); }
text("go");

const SID = new Uint8Array(32).fill(0x61), HASH = new Uint8Array(32).fill(0x33), MSG = new TextEncoder().encode("kexify refresh");

/** One sign over the pipe; reports [1] ok / [0] failed to Rust and returns whether it worked. */
async function sign(kind: "ecdsa" | "eddsa", key: unknown, pub: Uint8Array): Promise<boolean> {
  let ok = false;
  try {
    if (kind === "ecdsa") {
      const [sig] = await mpc.ecdsa2pSign(pipe, 0, NAMES, key, SID, [HASH]);
      ok = mpc.verifyDer(NID_secp256k1, pub, HASH, sig);
    } else {
      const sig = await mpc.schnorr2pEddsaSign(pipe, 0, NAMES, key, MSG);
      ok = ed25519.verify(sig, MSG, ed25519Compressed(pub));
    }
  } catch { ok = false; }
  control(new Uint8Array([ok ? 1 : 0]));
  return ok;
}

const times: Record<string, number[]> = { ecdsa: [], eddsa: [] };
for (const kind of ["ecdsa", "eddsa"] as const) {
  const E = kind === "ecdsa";
  const info = (k: unknown) => (E ? mpc.ecdsa2pKeyInfo(k) : mpc.ecKey2pInfo(k));
  const old = E ? await mpc.ecdsa2pDkg(pipe, 0, NAMES, NID_secp256k1) : await mpc.ecKey2pDkg(pipe, 0, NAMES, NID_ED25519);
  const pub = info(old).publicKey;
  control(pub);

  let cur = old;
  for (let i = 0; i < RUNS; i++) {
    const t0 = performance.now();
    cur = E ? await mpc.ecdsa2pRefresh(pipe, 0, NAMES, cur) : await mpc.ecKey2pRefresh(pipe, 0, NAMES, cur);
    times[kind].push(ms(t0));
    assert(eq(info(cur).publicKey, pub) && info(cur).roleIndex === 0, `${kind} refresh ${i} keeps the key`);
    control(info(cur).publicKey);
  }
  assert(await sign(kind, cur, pub), `${kind} new + new signs`);
  assert(!(await sign(kind, old, pub)), `${kind} old client + new server fails`);
  assert(!(await sign(kind, cur, pub)), `${kind} new client + old server fails`);
}
console.error(`refresh ms (WASM P1, ${RUNS} runs): ecdsa ${times.ecdsa.join(", ")}; eddsa ${times.eddsa.join(", ")}`);
text("done");
process.exit(0);
