/**
 * HD Keyset Demo (two-party)
 *
 * One DKG gives a keyset; keys for any path are derived on demand:
 *   1. Keyset DKG (secp256k1)
 *   2. Account node -> BIP32 xpub (both parties agree on it)
 *   3. Derive several keys in one round and sign with one of them
 *   4. Refresh the keyset: same root, same derived keys
 *   5. Serialize / deserialize the keyset (that is all a party stores)
 *   6. Upgrade an existing ECDSA-2P key into a keyset (address unchanged)
 *   7. The same for Ed25519 (EdDSA-2P)
 *
 * Hardened path = account label (a 2-party VRF step, not BIP32 hardened);
 * non-hardened paths below it are standard BIP32 public derivation.
 *
 * Each concurrent MPC party uses its own CbMpc instance (one WASM module each).
 */

import { initCbMpc, CbMpc, NID_secp256k1, NID_ED25519 } from "../dist/index";
import type { DataTransport } from "../dist/index";
import { createMockNetwork } from "./mock-transport";

const PARTY_NAMES: [string, string] = ["client", "server"];
const H = 0x80000000;
const ACCOUNT = [44 + H, 60 + H, 0 + H]; // e.g. m/44'/60'/0' (EVM)

/** Run the same 2-party call on both parties over a fresh in-memory network. */
async function both<T>(mpcs: CbMpc[], fn: (mpc: CbMpc, t: DataTransport, party: number) => Promise<T>): Promise<[T, T]> {
  const net = createMockNetwork(2);
  return (await Promise.all(mpcs.map((m, i) => fn(m, net[i], i)))) as [T, T];
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

async function sha256(text: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text) as BufferSource));
}

async function main() {
  console.log("=== HD Keyset Demo ===\n");
  const mpcs = await Promise.all([initCbMpc(), initCbMpc()]);
  const [mpc0, mpc1] = mpcs;

  // 1. Keyset DKG
  console.log("1. Keyset DKG (secp256k1)...");
  const keysets = await both(mpcs, (m, t, i) => m.hdEcdsa2pDkg(t, i, PARTY_NAMES, NID_secp256k1));
  const root = mpc0.hdEcdsa2pKeysetInfo(keysets[0]);
  console.log(`   Root public key: ${hex(root.publicKey).slice(0, 34)}...`);

  // 2. Account node (xpub material)
  console.log("\n2. Account node for m/44'/60'/0'...");
  const [node0, node1] = await both(mpcs, (m, t, i) => m.hdEcdsa2pAccountNode(t, i, PARTY_NAMES, keysets[i], ACCOUNT));
  console.log(`   Public key: ${hex(node0.publicKey)}`);
  console.log(`   Chain code: ${hex(node0.chainCode)}`);
  console.log(`   Parties agree: ${hex(node0.publicKey) === hex(node1.publicKey) && hex(node0.chainCode) === hex(node1.chainCode)}`);
  console.log("   (give publicKey + chainCode to any BIP32 library to derive child addresses without MPC)");

  // 3. Derive keys for 0/0, 0/1, 1/0 in one round; sign with 0/1
  console.log("\n3. Derive 0/0, 0/1, 1/0 and sign with 0/1...");
  const paths = [[0, 0], [0, 1], [1, 0]];
  const [keys0, keys1] = await both(mpcs, (m, t, i) => m.hdEcdsa2pDerive(t, i, PARTY_NAMES, keysets[i], ACCOUNT, paths));
  paths.forEach((p, j) => console.log(`   ${p.join("/")}: ${hex(mpc0.ecdsa2pKeyInfo(keys0[j]).publicKey).slice(0, 34)}...`));
  const hash = await sha256("hello from an HD key");
  const [sigs] = await both(mpcs, (m, t, i) =>
    m.ecdsa2pSign(t, i, PARTY_NAMES, i ? keys1[1] : keys0[1], new Uint8Array(0), [hash]));
  const pub01 = mpc0.ecdsa2pKeyInfo(keys0[1]).publicKey;
  console.log(`   Signature valid: ${mpc0.verifyDer(NID_secp256k1, pub01, hash, sigs[0])}`);

  // 4. Refresh
  console.log("\n4. Refresh keyset...");
  const refreshed = await both(mpcs, (m, t, i) => m.hdEcdsa2pRefresh(t, i, PARTY_NAMES, keysets[i]));
  const [again] = await both(mpcs, (m, t, i) => m.hdEcdsa2pDerive(t, i, PARTY_NAMES, refreshed[i], ACCOUNT, [[0, 1]]));
  console.log(`   Root unchanged: ${hex(mpc0.hdEcdsa2pKeysetInfo(refreshed[0]).publicKey) === hex(root.publicKey)}`);
  console.log(`   0/1 unchanged:  ${hex(mpc0.ecdsa2pKeyInfo(again[0]).publicKey) === hex(pub01)}`);

  // 5. Serialize / deserialize
  console.log("\n5. Serialize keyset (what each party stores)...");
  const blob0 = mpc0.serializeHdEcdsa2p(refreshed[0]);
  const blob1 = mpc1.serializeHdEcdsa2p(refreshed[1]);
  console.log(`   Party 0: ${blob0.length} parts, ${blob0.reduce((s, p) => s + p.length, 0)} bytes`);
  const restored = [mpc0.deserializeHdEcdsa2p(blob0), mpc1.deserializeHdEcdsa2p(blob1)];
  const [fromBlob] = await both(mpcs, (m, t, i) => m.hdEcdsa2pDerive(t, i, PARTY_NAMES, restored[i], ACCOUNT, [[0, 1]]));
  console.log(`   Restored keyset derives the same 0/1: ${hex(mpc0.ecdsa2pKeyInfo(fromBlob[0]).publicKey) === hex(pub01)}`);

  // 6. Upgrade an existing ECDSA-2P key
  console.log("\n6. Upgrade an existing ECDSA-2P key into a keyset...");
  const legacy = await both(mpcs, (m, t, i) => m.ecdsa2pDkg(t, i, PARTY_NAMES, NID_secp256k1));
  const upgraded = await both(mpcs, (m, t, i) => m.hdEcdsa2pFromKey(t, i, PARTY_NAMES, legacy[i]));
  const legacyPub = mpc0.ecdsa2pKeyInfo(legacy[0]).publicKey;
  console.log(`   Root == legacy key (address kept): ${hex(mpc0.hdEcdsa2pKeysetInfo(upgraded[0]).publicKey) === hex(legacyPub)}`);
  const [newKeys] = await both(mpcs, (m, t, i) => m.hdEcdsa2pDerive(t, i, PARTY_NAMES, upgraded[i], ACCOUNT, [[0, 0]]));
  console.log(`   New HD address key: ${hex(mpc0.ecdsa2pKeyInfo(newKeys[0]).publicKey).slice(0, 34)}...`);

  // 7. Ed25519
  console.log("\n7. Ed25519 keyset...");
  const SOL = [44 + H, 501 + H, 0 + H];
  const edKeysets = await both(mpcs, (m, t, i) => m.hdEddsa2pDkg(t, i, PARTY_NAMES, NID_ED25519));
  const [ed0, ed1] = await both(mpcs, (m, t, i) => m.hdEddsa2pDerive(t, i, PARTY_NAMES, edKeysets[i], SOL, [[0]]));
  const msg = new TextEncoder().encode("hello ed25519");
  const [edSig] = await both(mpcs, (m, t, i) => m.schnorr2pEddsaSign(t, i, PARTY_NAMES, i ? ed1[0] : ed0[0], msg));
  console.log(`   Derived key: ${hex(mpc0.ecKey2pInfo(ed0[0]).publicKey).slice(0, 34)}...`);
  console.log(`   Signature: ${edSig.length} bytes (verify with any Ed25519 library)`);

  console.log("\n=== Demo complete ===");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
