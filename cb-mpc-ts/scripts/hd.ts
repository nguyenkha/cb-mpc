// HD keyset tests (WASM): DKG, derive + sign, account node vs a standard BIP32
// library, refresh, serialization, upgrading existing keys, error paths.
//
// The "account node == upstream derive" checks are the drift guard for
// capi/hd_keyset.inc's re-implementation of upstream's hardened step: if
// upstream changes its derivation, these fail instead of silently producing
// wrong xpubs.
//
// Usage (from cb-mpc-ts/): bun run scripts/hd.ts

import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { resolve } from "node:path";
import { HDKey } from "@scure/bip32";

const M: any = await import(resolve("dist/index.js"));
const P = ["client", "server"] as [string, string];
const H = 0x80000000;
const BIP44_BTC = [44 + H, 0 + H, 0 + H];
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const sha = (s: string) => new Uint8Array(createHash("sha256").update(s).digest());

function pair() {
  const q: Uint8Array[][] = [[], []];
  const w: any[] = [null, null];
  return [0, 1].map((i) => ({
    async send(_r: number, m: Uint8Array) { const o = 1 - i; if (w[o]) { const f = w[o]; w[o] = null; f(m.slice()); } else q[o].push(m.slice()); return 0; },
    async receive() { return q[i].length ? q[i].shift()! : new Promise<Uint8Array>((r) => (w[i] = r)); },
    async receiveAll(s: number[]) { return Promise.all(s.map(() => this.receive())); },
  }));
}
/** Run the same 2-party call on both parties. */
async function both<T>(ms: any[], fn: (m: any, t: any, i: number) => Promise<T>): Promise<[T, T]> {
  const t = pair();
  return (await Promise.all(ms.map((m, i) => fn(m, t[i], i)))) as [T, T];
}
const compress = (sec1: Uint8Array) => { const o = new Uint8Array(33); o[0] = 0x02 | (sec1[64] & 1); o.set(sec1.slice(1, 33), 1); return o; };
const edEncode = (sec1: Uint8Array) => { const p = new Uint8Array(32); for (let i = 0; i < 32; i++) p[i] = sec1[64 - i]; p[31] |= (sec1[32] & 1) << 7; return p; };
const edVerify = (pub32: Uint8Array, msg: Uint8Array, sig: Uint8Array) =>
  nodeVerify(null, msg, createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub32]), format: "der", type: "spki" }), sig);

let pass = 0, fail = 0;
async function check(name: string, fn: () => Promise<void>) {
  const t0 = Date.now();
  try { await fn(); pass++; console.log(`PASS ${name} (${Date.now() - t0} ms)`); }
  catch (e) { fail++; console.log(`FAIL ${name}: ${(e as Error).message}`); }
}
function assert(c: unknown, msg: string): asserts c { if (!c) throw new Error(msg); }
async function expectThrow(fn: () => Promise<unknown> | unknown, kind?: any) {
  try { await fn(); } catch (e) { if (kind && !(e instanceof kind)) throw new Error(`wrong error: ${(e as Error).name}: ${(e as Error).message}`); return; }
  throw new Error("expected an error");
}

const ms = [await M.initCbMpc(), await M.initCbMpc()];
const h = sha("hd-sign");

// ---------------------------------------------------------------- ECDSA ----
for (const [cname, curve] of [["secp256k1", M.NID_secp256k1], ["P-256", M.NID_X9_62_prime256v1]] as const) {
  let ks: any[] = [];
  await check(`${cname}: keyset DKG, both parties see the same root`, async () => {
    ks = await both(ms, (m, t, i) => m.hdEcdsa2pDkg(t, i, P, curve));
    const [a, b] = ks.map((k, i) => ms[i].hdEcdsa2pKeysetInfo(k));
    assert(hex(a.publicKey) === hex(b.publicKey) && a.roleIndex === 0 && b.roleIndex === 1 && a.curveCode === curve, "root mismatch");
  });

  const paths = [[0, 0], [0, 1], [1, 0], [1, 7], []];
  let derivedPubs: string[] = [];
  await check(`${cname}: derive 5 paths in one run, sign with each, verify`, async () => {
    const [k0, k1] = await both(ms, (m, t, i) => m.hdEcdsa2pDerive(t, i, P, ks[i], BIP44_BTC, paths));
    assert(k0.length === 5 && k1.length === 5, "count");
    derivedPubs = [];
    for (let j = 0; j < paths.length; j++) {
      const pub = ms[0].ecdsa2pKeyInfo(k0[j]).publicKey;
      assert(hex(pub) === hex(ms[1].ecdsa2pKeyInfo(k1[j]).publicKey), `party pubs differ at ${j}`);
      derivedPubs.push(hex(pub));
      const [s] = await both(ms, (m, t, i) => m.ecdsa2pSign(t, i, P, i ? k1[j] : k0[j], new Uint8Array(0), [h]));
      assert(ms[0].verifyDer(curve, pub, h, s[0]), `sig invalid at path ${paths[j]}`);
    }
    assert(new Set(derivedPubs).size === 5, "derived keys not distinct");
    const root = hex(ms[0].hdEcdsa2pKeysetInfo(ks[0]).publicKey);
    assert(!derivedPubs.includes(root), "derived key equals root");
  });

  await check(`${cname}: account node == upstream derive (drift guard)`, async () => {
    const [n0, n1] = await both(ms, (m, t, i) => m.hdEcdsa2pAccountNode(t, i, P, ks[i], BIP44_BTC));
    assert(hex(n0.publicKey) === hex(n1.publicKey) && hex(n0.chainCode) === hex(n1.chainCode), "parties disagree on node");
    assert(n0.publicKey.length === 33 && n0.chainCode.length === 32, "node sizes");
    // empty non-hardened path = the node itself
    assert(hex(n0.publicKey) === hex(compress(Buffer.from(derivedPubs[4], "hex"))), "node pub != derive([])");
  });

  if (cname === "secp256k1") {
    await check(`secp256k1: xpub children (@scure/bip32) == MPC-derived keys`, async () => {
      const [n0] = await both(ms, (m, t, i) => m.hdEcdsa2pAccountNode(t, i, P, ks[i], BIP44_BTC));
      const xpub = new HDKey({ publicKey: n0.publicKey, chainCode: n0.chainCode });
      for (let j = 0; j < 4; j++) {
        const [c, idx] = paths[j];
        const child = xpub.deriveChild(c).deriveChild(idx);
        assert(hex(child.publicKey!) === hex(compress(Buffer.from(derivedPubs[j], "hex"))), `BIP32 child ${c}/${idx} differs`);
      }
      // the xpub string round-trips through a standard encoder
      assert(HDKey.fromExtendedKey(xpub.publicExtendedKey).publicKey!.length === 33, "xpub encode");
    });
  }

  await check(`${cname}: refresh keeps root and derived keys, refreshed keyset signs`, async () => {
    const ks2 = await both(ms, (m, t, i) => m.hdEcdsa2pRefresh(t, i, P, ks[i]));
    assert(hex(ms[0].hdEcdsa2pKeysetInfo(ks2[0]).publicKey) === hex(ms[0].hdEcdsa2pKeysetInfo(ks[0]).publicKey), "root changed");
    const [k0, k1] = await both(ms, (m, t, i) => m.hdEcdsa2pDerive(t, i, P, ks2[i], BIP44_BTC, [paths[2]]));
    assert(hex(ms[0].ecdsa2pKeyInfo(k0[0]).publicKey) === derivedPubs[2], "derived key changed after refresh");
    const [s] = await both(ms, (m, t, i) => m.ecdsa2pSign(t, i, P, i ? k1[0] : k0[0], new Uint8Array(0), [h]));
    assert(ms[0].verifyDer(curve, Buffer.from(derivedPubs[2], "hex"), h, s[0]), "sig after refresh");
  });

  await check(`${cname}: serialize -> deserialize keyset, derive same key`, async () => {
    const ser = ks.map((k, i) => ms[i].serializeHdEcdsa2p(k));
    assert(ser[0].length === 8, "parts");
    const ks3 = ser.map((s, i) => ms[i].deserializeHdEcdsa2p(s));
    assert(ser.map((s, i) => ms[i].serializeHdEcdsa2p(ks3[i]).map(hex).join()).join() === ser.map((s) => s.map(hex).join()).join(), "re-serialize differs");
    const [k0] = await both(ms, (m, t, i) => m.hdEcdsa2pDerive(t, i, P, ks3[i], BIP44_BTC, [paths[1]]));
    assert(hex(ms[0].ecdsa2pKeyInfo(k0[0]).publicKey) === derivedPubs[1], "derived key changed after reload");
  });
}

await check("secp256k1: upgrade existing key -> keyset; root unchanged; old key still signs", async () => {
  const old = await both(ms, (m, t, i) => m.ecdsa2pDkg(t, i, P, M.NID_secp256k1));
  const oldPub = ms[0].ecdsa2pKeyInfo(old[0]).publicKey;
  const ks = await both(ms, (m, t, i) => m.hdEcdsa2pFromKey(t, i, P, old[i]));
  assert(hex(ms[0].hdEcdsa2pKeysetInfo(ks[0]).publicKey) === hex(oldPub), "root != old key");
  const [k0, k1] = await both(ms, (m, t, i) => m.hdEcdsa2pDerive(t, i, P, ks[i], BIP44_BTC, [[0, 3]]));
  const pub = ms[0].ecdsa2pKeyInfo(k0[0]).publicKey;
  assert(hex(pub) !== hex(oldPub), "derived == old");
  let [s] = await both(ms, (m, t, i) => m.ecdsa2pSign(t, i, P, i ? k1[0] : k0[0], new Uint8Array(0), [h]));
  assert(ms[0].verifyDer(M.NID_secp256k1, pub, h, s[0]), "derived sig");
  [s] = await both(ms, (m, t, i) => m.ecdsa2pSign(t, i, P, old[i], new Uint8Array(0), [h]));
  assert(ms[0].verifyDer(M.NID_secp256k1, oldPub, h, s[0]), "old key sig");
  // the node from an upgraded keyset is a valid xpub too
  const [n] = await both(ms, (m, t, i) => m.hdEcdsa2pAccountNode(t, i, P, ks[i], BIP44_BTC));
  const child = new HDKey({ publicKey: n.publicKey, chainCode: n.chainCode }).deriveChild(0).deriveChild(3);
  assert(hex(child.publicKey!) === hex(compress(pub)), "xpub child of upgraded keyset");
});

await check("upgrade with shares of two different keys is rejected", async () => {
  const a = await both(ms, (m, t, i) => m.ecdsa2pDkg(t, i, P, M.NID_secp256k1));
  const b = await both(ms, (m, t, i) => m.ecdsa2pDkg(t, i, P, M.NID_secp256k1));
  await expectThrow(() => both(ms, (m, t, i) => m.hdEcdsa2pFromKey(t, i, P, i ? b[1] : a[0])), M.CbMpcError);
});

// ---------------------------------------------------------------- EdDSA ----
let eks: any[] = [];
const SOL = [44 + H, 501 + H, 0 + H];
await check("Ed25519: keyset DKG, derive, sign + verify (node:crypto)", async () => {
  eks = await both(ms, (m, t, i) => m.hdEddsa2pDkg(t, i, P, M.NID_ED25519));
  const [k0, k1] = await both(ms, (m, t, i) => m.hdEddsa2pDerive(t, i, P, eks[i], SOL, [[0], [1], []]));
  const msg = new TextEncoder().encode("hd eddsa");
  const pubs = new Set<string>();
  for (let j = 0; j < 3; j++) {
    const pub = ms[0].ecKey2pInfo(k0[j]).publicKey;
    assert(hex(pub) === hex(ms[1].ecKey2pInfo(k1[j]).publicKey), "party pubs differ");
    pubs.add(hex(pub));
    const [sig] = await both(ms, (m, t, i) => m.schnorr2pEddsaSign(t, i, P, i ? k1[j] : k0[j], msg));
    assert(edVerify(edEncode(pub), msg, sig), `ed25519 sig invalid at ${j}`);
  }
  assert(pubs.size === 3, "not distinct");
  const [n] = await both(ms, (m, t, i) => m.hdEddsa2pAccountNode(t, i, P, eks[i], SOL));
  const nodeKey = ms[0].ecKey2pInfo(k0[2]).publicKey; // empty path = node
  assert(hex(n.publicKey).endsWith(hex(edEncode(nodeKey))) || hex(n.publicKey) === hex(compress(nodeKey)), `ed node != derive([]): ${hex(n.publicKey)}`);
});

await check("Ed25519: refresh + serialize keep keys", async () => {
  const before = ms[0].hdEddsa2pKeysetInfo(eks[0]).publicKey;
  const r = await both(ms, (m, t, i) => m.hdEddsa2pRefresh(t, i, P, eks[i]));
  const re = r.map((k, i) => ms[i].deserializeHdEddsa2p(ms[i].serializeHdEddsa2p(k)));
  assert(hex(ms[0].hdEddsa2pKeysetInfo(re[0]).publicKey) === hex(before), "root changed");
  const [a] = await both(ms, (m, t, i) => m.hdEddsa2pDerive(t, i, P, eks[i], SOL, [[1]]));
  const [b] = await both(ms, (m, t, i) => m.hdEddsa2pDerive(t, i, P, re[i], SOL, [[1]]));
  assert(hex(ms[0].ecKey2pInfo(a[0]).publicKey) === hex(ms[0].ecKey2pInfo(b[0]).publicKey), "derived changed");
});

await check("Ed25519: upgrade existing EdDSA-2P key", async () => {
  const old = await both(ms, (m, t, i) => m.ecKey2pDkg(t, i, P, M.NID_ED25519));
  const ks = await both(ms, (m, t, i) => m.hdEddsa2pFromKey(t, i, P, old[i]));
  assert(hex(ms[0].hdEddsa2pKeysetInfo(ks[0]).publicKey) === hex(ms[0].ecKey2pInfo(old[0]).publicKey), "root != old");
  const [k0, k1] = await both(ms, (m, t, i) => m.hdEddsa2pDerive(t, i, P, ks[i], SOL, [[4]]));
  const msg = new TextEncoder().encode("upgraded");
  const [sig] = await both(ms, (m, t, i) => m.schnorr2pEddsaSign(t, i, P, i ? k1[0] : k0[0], msg));
  assert(edVerify(edEncode(ms[0].ecKey2pInfo(k0[0]).publicKey), msg, sig), "sig");
});

// ---------------------------------------------------------------- errors ----
const ecKs = await both(ms, (m, t, i) => m.hdEcdsa2pDkg(t, i, P, M.NID_secp256k1));
await check("errors: hardened index in non-hardened path -> RangeError", () =>
  expectThrow(() => ms[0].hdEcdsa2pDerive(pair()[0], 0, P, ecKs[0], BIP44_BTC, [[H]]), RangeError));
await check("errors: empty non-hardened path list -> RangeError", () =>
  expectThrow(() => ms[0].hdEcdsa2pDerive(pair()[0], 0, P, ecKs[0], BIP44_BTC, []), RangeError));
await check("errors: duplicate paths -> CbMpcError", () =>
  expectThrow(() => ms[0].hdEcdsa2pDerive(pair()[0], 0, P, ecKs[0], BIP44_BTC, [[0, 1], [0, 1]]), M.CbMpcError));
await check("errors: party index != keyset role -> CbMpcError", () =>
  expectThrow(() => ms[0].hdEcdsa2pDerive(pair()[0], 1, P, ecKs[0], BIP44_BTC, [[0]]), M.CbMpcError));
await check("errors: ECDSA curve for EdDSA keyset DKG -> CbMpcError", () =>
  expectThrow(() => ms[0].hdEddsa2pDkg(pair()[0], 0, P, M.NID_secp256k1), M.CbMpcError));
await check("errors: tampered keyset (K from another curve / 7 parts / role 2) rejected", async () => {
  const ser: Uint8Array[] = ms[0].serializeHdEcdsa2p(ecKs[0]);
  const edSer: Uint8Array[] = ms[0].serializeHdEddsa2p(eks[0]);
  const swapK = ser.map((x, i) => (i === 6 ? edSer[4] : x));
  await expectThrow(() => ms[0].deserializeHdEcdsa2p(swapK), M.CbMpcError);
  await expectThrow(() => ms[0].deserializeHdEcdsa2p(ser.slice(0, 7)), M.CbMpcError);
  const role2 = ser.map((x, i) => (i === 0 ? new Uint8Array([0, 0, 0, 2]) : x));
  await expectThrow(() => ms[0].deserializeHdEcdsa2p(role2), M.CbMpcError);
  // an ECDSA keyset blob is not an EdDSA keyset
  await expectThrow(() => ms[0].deserializeHdEddsa2p(ser), M.CbMpcError);
});
await check("errors: keyset info on null handle -> throws", () => expectThrow(() => ms[0].hdEcdsa2pKeysetInfo(0)));

console.log(`\n${pass}/${pass + fail} passed`);
process.exit(fail ? 1 : 0);
