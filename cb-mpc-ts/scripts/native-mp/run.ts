// Multi-party protocol test on the native backends (bun:ffi and koffi), one
// worker per party. Signatures are verified independently (WASM verifyDer /
// node:crypto Ed25519).
//
// Usage (from cb-mpc-ts/): bun run scripts/native-mp/run.ts [path/to/libcbmpc.(dylib|so)]

import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { resolve } from "node:path";
import { createMailboxes } from "./channel.ts";

const distPath = resolve("dist/index.js");
const M: any = await import(distPath);
const libPath = resolve(process.argv[2] || `prebuilds/${process.platform}-${process.arch}/libcbmpc.${process.platform === "darwin" ? "dylib" : "so"}`);
const wasm = await M.initCbMpc();
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

function runParties(n: number, backend: string, scenario: any): Promise<any[]> {
  const boxes = createMailboxes(n);
  return Promise.all(
    Array.from({ length: n }, (_, idx) => {
      const w = new Worker(new URL("./party.ts", import.meta.url).href);
      return new Promise<any>((res, rej) => {
        w.onmessage = (ev) => {
          w.terminate();
          ev.data.ok ? res(ev.data.out) : rej(new Error(`party ${idx}: ${ev.data.error}`));
        };
        w.onerror = (e) => rej(e);
        w.postMessage({ idx, n, boxes, backend, libPath, distPath, scenario });
      });
    }),
  );
}

function ed25519Verify(sec1: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  const x = sec1.slice(1, 33), y = sec1.slice(33, 65);
  const pub = new Uint8Array(32);
  for (let i = 0; i < 32; i++) pub[i] = y[31 - i];
  pub[31] |= (x[31] & 1) << 7;
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub]), format: "der", type: "spki" });
  return nodeVerify(null, msg, key, sig);
}

function ed25519VerifyCompressed(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub]), format: "der", type: "spki" });
  return nodeVerify(null, msg, key, sig);
}

const results: [string, boolean, string?][] = [];
async function check(name: string, fn: () => Promise<void>) {
  const t = Date.now();
  try {
    await fn();
    results.push([name, true]);
    console.log(`PASS ${name} (${Date.now() - t} ms)`);
  } catch (e) {
    results.push([name, false, (e as Error).message]);
    console.log(`FAIL ${name}: ${(e as Error).message.split("\n")[0]}`);
  }
}

const hash = new Uint8Array(createHash("sha256").update("native-mp").digest());
const text = new TextEncoder().encode("native-mp eddsa");

for (const backend of ["bun", "koffi"]) {
  for (const [cname, curve] of [["secp256k1", M.NID_secp256k1], ["P-256", M.NID_X9_62_prime256v1]] as const) {
    await check(`${backend}: ECDSA-2P ${cname} dkg, sign, refresh, sign`, async () => {
      const [r0, r1] = await runParties(2, backend, { kind: "ecdsa2p", curve, msg: hash });
      if (hex(r0.pub) !== hex(r1.pub)) throw new Error("pub mismatch");
      if (!wasm.verifyDer(curve, r0.pub, hash, r0.sig)) throw new Error("sig invalid");
      if (!wasm.verifyDer(curve, r0.pub, hash, r0.sig2)) throw new Error("sig after refresh invalid");
      // keys from native load + sign on WASM
      const k = r0.ser, k1 = r1.ser;
      const [w0, w1] = [wasm.deserializeEcdsa2p(k), (await M.initCbMpc()).deserializeEcdsa2p(k1)];
      if (hex(wasm.ecdsa2pKeyInfo(w0).publicKey) !== hex(r0.pub)) throw new Error("native->wasm key load");
      void w1;
    });
  }
  await check(`${backend}: EdDSA-2P dkg, sign`, async () => {
    const [r0, r1] = await runParties(2, backend, { kind: "eddsa2p", msg: text });
    if (hex(r0.pub) !== hex(r1.pub)) throw new Error("pub mismatch");
    if (!ed25519Verify(r0.pub, text, r0.sig)) throw new Error("sig invalid");
  });
  await check(`${backend}: EC-key MP 3p secp256k1 dkg, refresh, ECDSA-MP sign`, async () => {
    const rs = await runParties(3, backend, { kind: "mp", curve: M.NID_secp256k1, msg: hash });
    if (!wasm.verifyDer(M.NID_secp256k1, rs[0].pub, hash, rs[0].sig)) throw new Error("sig invalid");
  });
  await check(`${backend}: EC-key MP 3p Ed25519 dkg, refresh, EdDSA-MP sign`, async () => {
    const rs = await runParties(3, backend, { kind: "mp", curve: M.NID_ED25519, msg: text });
    if (!ed25519Verify(rs[0].pub, text, rs[0].sig)) throw new Error("sig invalid");
  });
  for (const [cname, curve] of [["secp256k1", M.NID_secp256k1], ["Ed25519", M.NID_ED25519]] as const) {
    await check(`${backend}: AC ${cname} dkg 2-of-3, lost-device reshare, every pair signs, refresh`, async () => {
      const ALL = ["iphone", "mac", "server"];
      const ac = M.thresholdOf(2, ALL);
      const ac2 = (op: string, names: string[], extra: any = {}) =>
        runParties(names.length, backend, { kind: "ac", op, names, curve, ac, msg: curve === M.NID_ED25519 ? text : hash, ...extra });
      const byName = (names: string[], rs: any[], f = "blob") => Object.fromEntries(names.map((n, i) => [n, rs[i][f]]));
      const g0 = byName(ALL, await ac2("dkg", ALL));
      const pub = wasm.acKeyInfo(g0.iphone).publicKey;
      const g1rs = await ac2("reshare", ALL, { blobs: g0, oldAc: ac, dealers: ["mac", "server"], pub });
      if (!g1rs.every((r: any) => hex(r.pub) === hex(pub))) throw new Error("public key changed");
      let g1 = byName(ALL, g1rs);
      const signsWith = async (keys: any, pair: string[]) => {
        const [r0] = await ac2("sign", pair, { blobs: keys });
        return curve === M.NID_ED25519 ? ed25519VerifyCompressed(pub, text, r0.sig) : wasm.verifyDer(curve, pub, hash, r0.sig);
      };
      for (const pair of [["iphone", "server"], ["mac", "server"], ["iphone", "mac"]])
        if (!(await signsWith(g1, pair))) throw new Error(`${pair} did not sign`);
      g1 = byName(ALL, await ac2("refresh", ALL, { blobs: g1 }));
      if (!(await signsWith(g1, ["iphone", "mac"]))) throw new Error("no signature after refresh");
      let mixedRejected = false;
      try { mixedRejected = !(await signsWith({ iphone: g0.iphone, server: g1.server }, ["iphone", "server"])); } catch { mixedRejected = true; }
      if (!mixedRejected) throw new Error("old iphone share signed with the new server share");
    });
  }
  await check(`${backend}: agreeRandom`, async () => {
    const [r0, r1] = await runParties(2, backend, { kind: "agree" });
    if (hex(r0.rand) !== hex(r1.rand) || r0.rand.length !== 32) throw new Error("outputs differ");
  });
  await check(`${backend}: ECDSA-2P key made on WASM, signed on native`, async () => {
    // DKG on WASM (async in-process), then sign on native workers.
    const [a, b] = [await M.initCbMpc(), await M.initCbMpc()];
    const q: Uint8Array[][] = [[], []]; const waiters: any[] = [null, null];
    const tr = (i: number) => ({
      async send(_r: number, m: Uint8Array) { const o = 1 - i; if (waiters[o]) { const w = waiters[o]; waiters[o] = null; w(m.slice()); } else q[o].push(m.slice()); return 0; },
      async receive() { return q[i].length ? q[i].shift()! : new Promise<Uint8Array>((r) => (waiters[i] = r)); },
      async receiveAll(s: number[]) { return Promise.all(s.map(() => this.receive())); },
    });
    const [k0, k1] = await Promise.all([a.ecdsa2pDkg(tr(0), 0, ["p0", "p1"], M.NID_secp256k1), b.ecdsa2pDkg(tr(1), 1, ["p0", "p1"], M.NID_secp256k1)]);
    const keys = [a.serializeEcdsa2p(k0), b.serializeEcdsa2p(k1)];
    const [r0] = await runParties(2, backend, { kind: "loadsign", keys, msg: hash });
    if (!wasm.verifyDer(M.NID_secp256k1, a.ecdsa2pKeyInfo(k0).publicKey, hash, r0.sig)) throw new Error("sig invalid");
  });
  await check(`${backend}: HD keyset made on WASM, derived + signed on native, node matches WASM`, async () => {
    const [a, b] = [await M.initCbMpc(), await M.initCbMpc()];
    const mk = () => { const q: Uint8Array[][] = [[], []]; const ws: any[] = [null, null];
      return [0, 1].map((i) => ({
        async send(_r: number, m: Uint8Array) { const o = 1 - i; if (ws[o]) { const w = ws[o]; ws[o] = null; w(m.slice()); } else q[o].push(m.slice()); return 0; },
        async receive() { return q[i].length ? q[i].shift()! : new Promise<Uint8Array>((r) => (ws[i] = r)); },
        async receiveAll(s: number[]) { return Promise.all(s.map(() => this.receive())); } })); };
    let t = mk();
    const ks = await Promise.all([a.hdEcdsa2pDkg(t[0], 0, ["p0", "p1"], M.NID_secp256k1), b.hdEcdsa2pDkg(t[1], 1, ["p0", "p1"], M.NID_secp256k1)]);
    const hardened = [0x8000002c, 0x80000000, 0x80000002], path = [1, 9];
    t = mk();
    const [wk] = await Promise.all([a.hdEcdsa2pDerive(t[0], 0, ["p0", "p1"], ks[0], hardened, [path]), b.hdEcdsa2pDerive(t[1], 1, ["p0", "p1"], ks[1], hardened, [path])]);
    t = mk();
    const [wn] = await Promise.all([a.hdEcdsa2pAccountNode(t[0], 0, ["p0", "p1"], ks[0], hardened), b.hdEcdsa2pAccountNode(t[1], 1, ["p0", "p1"], ks[1], hardened)]);
    const keysets = [a.serializeHdEcdsa2p(ks[0]), b.serializeHdEcdsa2p(ks[1])];
    const [r0, r1] = await runParties(2, backend, { kind: "hdsign", keysets, hardened, path, msg: hash });
    const wasmPub = a.ecdsa2pKeyInfo(wk[0]).publicKey;
    if (hex(r0.pub) !== hex(wasmPub) || hex(r1.pub) !== hex(wasmPub)) throw new Error("native derive != WASM derive");
    if (hex(r0.node.publicKey) !== hex(wn.publicKey) || hex(r0.node.chainCode) !== hex(wn.chainCode)) throw new Error("native node != WASM node");
    if (!wasm.verifyDer(M.NID_secp256k1, wasmPub, hash, r0.sig)) throw new Error("sig invalid");
  });
  await check(`${backend}: zkDl prove/verify cross-backend (aux > 2^32)`, async () => {
    const n = backend === "koffi" ? await M.initCbMpcKoffi(libPath) : await M.initCbMpcBunFfi(libPath);
    const aux = 2 ** 40 + 12345;
    const sid = new Uint8Array(32).fill(7);
    for (const [prover, verifier] of [[n, wasm], [wasm, n]]) {
      const c = prover.createCurve(M.NID_secp256k1);
      const w = prover.randomScalar(c);
      const Q = prover.mulGenerator(c, w);
      const proof = await prover.zkDlProve(Q, w, sid, aux);
      const Qv = verifier.pointFromBytes(prover.pointToBytes(Q));
      if (!(await verifier.zkDlVerify(Qv, proof, sid, aux))) throw new Error("valid proof rejected");
      if (await verifier.zkDlVerify(Qv, proof, sid, aux + 1)) throw new Error("proof accepted with wrong aux");
    }
  });
}

const failed = results.filter((r) => !r[1]);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);
