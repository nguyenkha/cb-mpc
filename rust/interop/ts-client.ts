// cb-mpc-ts client party (P1, "client") for the Rust interop test (rust/cbmpc/tests/interop_ts.rs),
// which runs the server party (P2) in Rust and talks to this script over stdin/stdout.
// Frames: [tag:u8][len:u32 BE][bytes], tag "M" = protocol message, "C" = control data. The steps
// are fixed and mirrored in the Rust test; any failure exits non-zero.
import { initCbMpc, NID_secp256k1, NID_ED25519, type DataTransport } from "cb-mpc";
import { ed25519 } from "@noble/curves/ed25519.js";
import { writeSync } from "fs";

const NAMES: [string, string] = ["client", "server"];
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
const readControl = () => expectFrame("C");

const pipe: DataTransport = {
  async send(_receiver, message) { writeFrame("M", message); return 0; },
  receive: () => expectFrame("M"),
  receiveAll: (senders) => Promise.all(senders.map(() => expectFrame("M"))),
};

/** cb-mpc point 0x04 || X || Y (Ed25519) to the RFC 8032 encoding. */
function ed25519Compressed(oct: Uint8Array): Uint8Array {
  const out = oct.slice(33, 65).reverse();
  out[31] |= (oct[32] & 1) << 7;
  return out;
}

const assert = (ok: boolean, what: string) => { if (!ok) throw new Error(`check failed: ${what}`); };

/** Sign hashes from the Rust side with `ecdsa` (a client key) and send the signatures back. */
async function ecdsaSign(mpc: Awaited<ReturnType<typeof initCbMpc>>, ecdsa: any) {
  const sid = await readControl();
  const hashes = [await readControl(), await readControl()];
  const sigs = await mpc.ecdsa2pSign(pipe, 0, NAMES, ecdsa, sid, hashes);
  const pub = mpc.ecdsa2pKeyInfo(ecdsa).publicKey;
  sigs.forEach((s, i) => assert(mpc.verifyDer(NID_secp256k1, pub, hashes[i], s), `ecdsa sig ${i}`));
  sigs.forEach(control);
}

async function eddsaSign(mpc: Awaited<ReturnType<typeof initCbMpc>>, eddsa: any) {
  const msg = await readControl();
  const sig = await mpc.schnorr2pEddsaSign(pipe, 0, NAMES, eddsa, msg);
  assert(ed25519.verify(sig, msg, ed25519Compressed(mpc.ecKey2pInfo(eddsa).publicKey)), "eddsa sig");
  control(sig);
}

const mpc = await initCbMpc();

const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Loads the server share Rust made (as recovery mode loads it in the browser): same public key,
 *  server role, and byte-identical re-serialization. Replies [1]. */
async function loadRustShare(publicKey: Uint8Array, kind: "ecdsa" | "eddsa") {
  const n = (await readControl())[0];
  const parts: Uint8Array[] = [];
  for (let i = 0; i < n; i++) parts.push(await readControl());
  const lib = await initCbMpc();
  if (kind === "ecdsa") {
    const k = lib.deserializeEcdsa2p(parts);
    const info = lib.ecdsa2pKeyInfo(k);
    assert(eq(info.publicKey, publicKey) && info.roleIndex === 1, "rust ecdsa share info");
    const again = lib.serializeEcdsa2p(k);
    assert(again.length === parts.length && again.every((p, i) => eq(p, parts[i])), "rust ecdsa share re-serializes");
  } else {
    const k = lib.deserializeEcKey2p(parts);
    const info = lib.ecKey2pInfo(k);
    assert(eq(info.publicKey, publicKey) && info.roleIndex === 1, "rust eddsa share info");
    const again = lib.serializeEcKey2p(k);
    assert(again.length === parts.length && again.every((p, i) => eq(p, parts[i])), "rust eddsa share re-serializes");
  }
  control(new Uint8Array([1]));
}

// 1-2. ECDSA-2P DKG against Rust, then a 2-hash batch sign.
const ecdsa = await mpc.ecdsa2pDkg(pipe, 0, NAMES, NID_secp256k1);
control(mpc.ecdsa2pKeyInfo(ecdsa).publicKey);
await loadRustShare(mpc.ecdsa2pKeyInfo(ecdsa).publicKey, "ecdsa");
await ecdsaSign(mpc, ecdsa);

// 3-4. EdDSA-2P (Schnorr) DKG against Rust, then a sign.
const eddsa = await mpc.ecKey2pDkg(pipe, 0, NAMES, NID_ED25519);
control(mpc.ecKey2pInfo(eddsa).publicKey);
await loadRustShare(mpc.ecKey2pInfo(eddsa).publicKey, "eddsa");
await eddsaSign(mpc, eddsa);

// 5. Keys made entirely by cb-mpc-ts (both parties here): hand the server parts to Rust, which
//    loads them, then sign with them across the pipe.
const local = () => {
  const q: Uint8Array[][] = [[], []];
  const waiting: (((m: Uint8Array) => void) | null)[] = [null, null];
  return [0, 1].map((me): DataTransport => ({
    async send(to, m) { const w = waiting[to]; if (w) { waiting[to] = null; w(new Uint8Array(m)); } else q[to].push(new Uint8Array(m)); return 0; },
    receive: () => new Promise((r) => { const m = q[me].shift(); if (m) r(m); else waiting[me] = r; }),
    receiveAll: (ss) => Promise.all(ss.map(() => new Promise<Uint8Array>((r) => { const m = q[me].shift(); if (m) r(m); else waiting[me] = r; }))),
  }));
};
const [ca, sa] = [mpc, await initCbMpc()];
let net = local();
const [cEcdsa, sEcdsa] = await Promise.all([ca.ecdsa2pDkg(net[0], 0, NAMES, NID_secp256k1), sa.ecdsa2pDkg(net[1], 1, NAMES, NID_secp256k1)]);
const [cb, sb] = [await initCbMpc(), await initCbMpc()];
net = local();
const [cEddsa, sEddsa] = await Promise.all([cb.ecKey2pDkg(net[0], 0, NAMES, NID_ED25519), sb.ecKey2pDkg(net[1], 1, NAMES, NID_ED25519)]);
const ecdsaParts = sa.serializeEcdsa2p(sEcdsa);
const eddsaParts = sb.serializeEcKey2p(sEddsa);
control(new Uint8Array([ecdsaParts.length]));
ecdsaParts.forEach(control);
control(ca.ecdsa2pKeyInfo(cEcdsa).publicKey);
control(new Uint8Array([eddsaParts.length]));
eddsaParts.forEach(control);
control(cb.ecKey2pInfo(cEddsa).publicKey);
await ecdsaSign(ca, cEcdsa);
await eddsaSign(cb, cEddsa);

control(new TextEncoder().encode("done"));
process.exit(0);
