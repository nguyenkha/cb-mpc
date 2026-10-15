// Interop test: cb-mpc-ts (WASM) parties <-> one party running upstream's
// original C API (party.c, linked against libcbmpc.a). Runs DKG + sign for
// ECDSA-2P, EdDSA-2P, ECDSA-MP and EdDSA-MP with the C party in every seat,
// then checks both sides agree on the public key and the signature verifies.
//
// Usage (from cb-mpc-ts/): bun run scripts/c-interop/run.ts <path/to/party-binary>

import { spawn } from "node:child_process";
import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { resolve } from "node:path";

const bin = resolve(process.argv[2] || "build/c-interop/party");
const M: any = await import(resolve("dist/index.js"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const C_CURVE: Record<number, number> = { [M.NID_X9_62_prime256v1]: 1, [M.NID_secp256k1]: 2, [M.NID_ED25519]: 3 };

function compressSec1(sec1: Uint8Array): Uint8Array {
  const out = new Uint8Array(33);
  out[0] = 0x02 | (sec1[64] & 1);
  out.set(sec1.slice(1, 33), 1);
  return out;
}
function ed25519Encode(sec1: Uint8Array): Uint8Array {
  const x = sec1.slice(1, 33), y = sec1.slice(33, 65);
  const pub = new Uint8Array(32);
  for (let i = 0; i < 32; i++) pub[i] = y[31 - i];
  pub[31] |= (x[31] & 1) << 7;
  return pub;
}
function ed25519Verify(pub32: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub32]), format: "der", type: "spki" });
  return nodeVerify(null, msg, key, sig);
}

/** Async mailbox per (receiver, sender). */
class Mailbox {
  private q = new Map<string, Uint8Array[]>();
  private w = new Map<string, ((m: Uint8Array) => void)[]>();
  put(to: number, from: number, m: Uint8Array) {
    const k = `${to}:${from}`;
    const ws = this.w.get(k);
    if (ws?.length) return ws.shift()!(m);
    if (!this.q.has(k)) this.q.set(k, []);
    this.q.get(k)!.push(m);
  }
  take(to: number, from: number): Promise<Uint8Array> {
    const k = `${to}:${from}`;
    const q = this.q.get(k);
    if (q?.length) return Promise.resolve(q.shift()!);
    return new Promise((r) => {
      if (!this.w.has(k)) this.w.set(k, []);
      this.w.get(k)!.push(r);
    });
  }
}

async function runMixed(proto: string, n: number, cSeat: number, curve: number, msg: Uint8Array) {
  const box = new Mailbox();
  const child = spawn(bin, [proto, String(cSeat), String(n), String(C_CURVE[curve]), hex(msg)], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (d) => (stderr += d));
  const cResults: Uint8Array[] = [];
  let buf = Buffer.alloc(0);
  child.stdout.on("data", (d: Buffer) => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 8) {
      const to = buf.readInt32LE(0), len = buf.readInt32LE(4);
      if (buf.length < 8 + len) break;
      const payload = new Uint8Array(buf.subarray(8, 8 + len));
      buf = buf.subarray(8 + len);
      if (to < 0) cResults.push(payload);
      else box.put(to, cSeat, payload);
    }
  });
  const cDone = new Promise<void>((res, rej) =>
    child.on("exit", (code) => (code === 0 ? res() : rej(new Error(`C party exit ${code}: ${stderr.trim()}`)))),
  );

  const transport = (self: number) => ({
    async send(to: number, m: Uint8Array) {
      if (to === cSeat) {
        const hdr = Buffer.alloc(8);
        hdr.writeInt32LE(self, 0);
        hdr.writeInt32LE(m.length, 4);
        child.stdin.write(Buffer.concat([hdr, Buffer.from(m)]));
      } else box.put(to, self, m.slice());
      return 0;
    },
    async receive(from: number) {
      return box.take(self, from);
    },
    async receiveAll(froms: number[]) {
      return Promise.all(froms.map((f) => box.take(self, f)));
    },
  });

  const names = Array.from({ length: n }, (_, i) => `p${i}`);
  const js = Array.from({ length: n }, (_, i) => i).filter((i) => i !== cSeat);
  const libs = await Promise.all(js.map(() => M.initCbMpc()));
  const jsRuns = js.map(async (i, j) => {
    const mpc = libs[j], t = transport(i);
    if (proto === "ecdsa2p") {
      const k = await mpc.ecdsa2pDkg(t, i, names, curve);
      const sig = (await mpc.ecdsa2pSign(t, i, names, k, new Uint8Array(0), [msg]))[0];
      return { idx: i, pub: mpc.ecdsa2pKeyInfo(k).publicKey, sig };
    }
    if (proto === "eddsa2p") {
      const k = await mpc.ecKey2pDkg(t, i, names, curve);
      const sig = await mpc.schnorr2pEddsaSign(t, i, names, k, msg);
      return { idx: i, pub: mpc.ecKey2pInfo(k).publicKey, sig };
    }
    if (proto.endsWith("ac")) {
      // Same flow as run_ac in party.c: dkg 2-of-3, mac + server reshare, all three sign.
      const acNames = ["iphone", "mac", "server"];
      const ac = M.thresholdOf(2, acNames);
      const dealers = ["mac", "server"];
      const g0 = await mpc.dkgAc(t, i, acNames, curve, ac, acNames);
      const pub = mpc.acKeyInfo(g0).publicKey;
      const x = i === 0 ? null : mpc.acToAdditiveShare(g0, ac, dealers);
      const g1 = await mpc.reshareFromAdditive(t, i, acNames, curve, pub, dealers, x, ac);
      const sig = await mpc.signAc(t, i, acNames, g1, ac, msg, 0);
      return { idx: i, pub, sig, compressed: true };
    }
    const c = mpc.createCurve(curve);
    const k = await mpc.ecKeyMpDkg(t, n, i, names, c);
    const sig = proto === "ecdsamp" ? await mpc.ecdsaMpSign(t, n, i, names, k, msg, 0) : await mpc.eddsaMpSign(t, n, i, names, k, msg, 0);
    return { idx: i, pub: mpc.ecKeyMpInfo(k).publicKey, sig };
  });

  const timeout = new Promise<never>((_, rej) => setTimeout(() => rej(new Error("timeout 120s")), 120000));
  try {
    const jsRes = await Promise.race([Promise.all([...jsRuns, cDone]), timeout]);
    return { js: (jsRes as any[]).slice(0, js.length), cPub: cResults[0], cSig: cResults[1] };
  } finally {
    child.kill();
  }
}

const results: [string, boolean][] = [];
async function check(name: string, fn: () => Promise<void>) {
  const t = Date.now();
  try {
    await fn();
    results.push([name, true]);
    console.log(`PASS ${name} (${Date.now() - t} ms)`);
  } catch (e) {
    results.push([name, false]);
    console.log(`FAIL ${name}: ${(e as Error).message.split("\n")[0]}`);
  }
}

const verifier = await M.initCbMpc();
const hash = new Uint8Array(createHash("sha256").update("c-interop").digest());
const text = new TextEncoder().encode("c-interop eddsa");

const cases: [string, number, number, Uint8Array][] = [
  ["ecdsa2p", 2, M.NID_secp256k1, hash],
  ["ecdsa2p", 2, M.NID_X9_62_prime256v1, hash],
  ["eddsa2p", 2, M.NID_ED25519, text],
  ["ecdsamp", 3, M.NID_secp256k1, hash],
  ["eddsamp", 3, M.NID_ED25519, text],
  ["ecdsaac", 3, M.NID_secp256k1, hash],
  ["eddsaac", 3, M.NID_ED25519, text],
];

for (const [proto, n, curve, msg] of cases) {
  for (let cSeat = 0; cSeat < n; cSeat++) {
    await check(`${proto} curve=${curve} C party at seat ${cSeat} of ${n}`, async () => {
      const r = await runMixed(proto, n, cSeat, curve, msg);
      const jsPub: Uint8Array = r.js[0].pub;
      const ed = curve === M.NID_ED25519;
      const jsPubC = r.js[0].compressed ? jsPub : ed ? ed25519Encode(jsPub) : compressSec1(jsPub);
      if (hex(jsPubC) !== hex(r.cPub)) throw new Error(`public key differs: js=${hex(jsPubC)} c=${hex(r.cPub)}`);
      for (const x of r.js) if (hex(x.pub) !== hex(jsPub)) throw new Error("JS parties disagree on public key");
      // seat 0 receives the signature (C party when cSeat == 0, else JS party 0)
      const sig: Uint8Array = cSeat === 0 ? r.cSig : r.js.find((x: any) => x.idx === 0).sig;
      const ok = ed ? ed25519Verify(jsPubC, msg, sig) : verifier.verifyDer(curve, jsPubC, msg, sig);
      if (!ok) throw new Error("signature does not verify");
    });
  }
}

const failed = results.filter((r) => !r[1]);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);
