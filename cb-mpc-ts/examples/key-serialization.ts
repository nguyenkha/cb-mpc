/**
 * Key Serialization Demo
 *
 * Demonstrates serializing and deserializing key shares for all key types:
 *   1. ECDSA 2P — serialize/deserialize, then sign with restored keys
 *   2. EC Key 2P (Schnorr/EdDSA) — serialize/deserialize, then sign with restored keys
 *   3. EC Key MP — serialize/deserialize, then sign with restored keys
 *
 * This is essential for production use where key shares must be persisted
 * to a database or Redis between protocol rounds.
 */

import { initCbMpc, CbMpc, NID_secp256k1, NID_ED25519 } from "../dist/index";
import type { Ecdsa2pKeyHandle, EcKey2pHandle, EcKeyMpHandle } from "../dist/index";
import { createMockNetwork } from "./mock-transport";

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", data as ArrayBufferView<ArrayBuffer>);
  return new Uint8Array(buf);
}

// ---------------------------------------------------------------------------
// 1. ECDSA 2P Key Serialization
// ---------------------------------------------------------------------------

async function demoEcdsa2p() {
  console.log("=== 1. ECDSA 2P Key Serialization ===\n");

  const [mpc0, mpc1] = await Promise.all([initCbMpc(), initCbMpc()]);
  const names: [string, string] = ["alice", "bob"];

  // DKG
  console.log("  Running DKG...");
  const transports = createMockNetwork(2);
  const [key0, key1] = await Promise.all([
    mpc0.ecdsa2pDkg(transports[0], 0, names, NID_secp256k1),
    mpc1.ecdsa2pDkg(transports[1], 1, names, NID_secp256k1),
  ]);

  const pubKey = hexEncode(mpc0.ecdsa2pKeyInfo(key0).publicKey);
  console.log(`  Public key: ${pubKey.slice(0, 32)}...`);

  // Serialize both key shares
  console.log("  Serializing key shares...");
  const parts0 = mpc0.serializeEcdsa2p(key0);
  const parts1 = mpc1.serializeEcdsa2p(key1);
  console.log(`  Party 0: ${parts0.length} parts, total ${parts0.reduce((s, p) => s + p.length, 0)} bytes`);
  console.log(`  Party 1: ${parts1.length} parts, total ${parts1.reduce((s, p) => s + p.length, 0)} bytes`);

  // Deserialize into fresh instances (simulating loading from DB)
  console.log("  Deserializing key shares...");
  const [mpc2, mpc3] = await Promise.all([initCbMpc(), initCbMpc()]);
  const restored0 = mpc2.deserializeEcdsa2p(parts0);
  const restored1 = mpc3.deserializeEcdsa2p(parts1);

  // Verify restored keys have same public key
  const restoredPubKey = hexEncode(mpc2.ecdsa2pKeyInfo(restored0).publicKey);
  console.log(`  Restored public key matches: ${pubKey === restoredPubKey}`);

  // Sign with restored keys
  console.log("  Signing with restored keys...");
  const msgHash = await sha256(new TextEncoder().encode("serialization test"));
  const sessionId = crypto.getRandomValues(new Uint8Array(32));
  const signTransports = createMockNetwork(2);

  const [sigs0, sigs1] = await Promise.all([
    mpc2.ecdsa2pSign(signTransports[0], 0, names, restored0, sessionId, [msgHash]),
    mpc3.ecdsa2pSign(signTransports[1], 1, names, restored1, sessionId, [msgHash]),
  ]);
  const sig = sigs0[0].length > 0 ? sigs0[0] : sigs1[0];
  const valid = mpc2.verifyDer(NID_secp256k1, mpc2.ecdsa2pKeyInfo(restored0).publicKey, msgHash, sig);
  console.log(`  Signature valid: ${valid}`);

  // Cleanup
  mpc0.freeEcdsa2pKey(key0);
  mpc1.freeEcdsa2pKey(key1);
  mpc2.freeEcdsa2pKey(restored0);
  mpc3.freeEcdsa2pKey(restored1);
  console.log();
}

// ---------------------------------------------------------------------------
// 2. EC Key 2P (Schnorr/EdDSA) Key Serialization
// ---------------------------------------------------------------------------

async function demoEcKey2p() {
  console.log("=== 2. EC Key 2P (EdDSA) Key Serialization ===\n");

  const [mpc0, mpc1] = await Promise.all([initCbMpc(), initCbMpc()]);
  const names: [string, string] = ["alice", "bob"];

  // DKG
  console.log("  Running DKG...");
  const transports = createMockNetwork(2);
  const [key0, key1] = await Promise.all([
    mpc0.ecKey2pDkg(transports[0], 0, names, NID_ED25519),
    mpc1.ecKey2pDkg(transports[1], 1, names, NID_ED25519),
  ]);

  const info0 = mpc0.ecKey2pInfo(key0);
  console.log(`  Public key: ${hexEncode(info0.publicKey).slice(0, 32)}...`);

  // Serialize
  console.log("  Serializing key shares...");
  const parts0 = mpc0.serializeEcKey2p(key0);
  const parts1 = mpc1.serializeEcKey2p(key1);
  console.log(`  Party 0: ${parts0.length} parts, total ${parts0.reduce((s, p) => s + p.length, 0)} bytes`);
  console.log(`  Party 1: ${parts1.length} parts, total ${parts1.reduce((s, p) => s + p.length, 0)} bytes`);

  // Deserialize
  console.log("  Deserializing key shares...");
  const [mpc2, mpc3] = await Promise.all([initCbMpc(), initCbMpc()]);
  const restored0 = mpc2.deserializeEcKey2p(parts0);
  const restored1 = mpc3.deserializeEcKey2p(parts1);

  const restoredInfo = mpc2.ecKey2pInfo(restored0);
  console.log(`  Restored public key matches: ${hexEncode(info0.publicKey) === hexEncode(restoredInfo.publicKey)}`);

  // Sign with restored keys
  console.log("  Signing with restored keys...");
  const msg = new TextEncoder().encode("EdDSA serialization test");
  const signTransports = createMockNetwork(2);

  const [sig0, sig1] = await Promise.all([
    mpc2.schnorr2pEddsaSign(signTransports[0], 0, names, restored0, msg),
    mpc3.schnorr2pEddsaSign(signTransports[1], 1, names, restored1, msg),
  ]);
  const sig = sig0.length > 0 ? sig0 : sig1;
  console.log(`  Signature (${sig.length} bytes): ${hexEncode(sig).slice(0, 32)}...`);

  // Cleanup
  mpc0.freeEcKey2p(key0);
  mpc1.freeEcKey2p(key1);
  mpc2.freeEcKey2p(restored0);
  mpc3.freeEcKey2p(restored1);
  console.log();
}

// ---------------------------------------------------------------------------
// 3. EC Key MP Serialization
// ---------------------------------------------------------------------------

async function demoEcKeyMp() {
  console.log("=== 3. EC Key MP Serialization ===\n");

  const names = ["alice", "bob", "charlie"];
  const [mpc0, mpc1, mpc2] = await Promise.all([initCbMpc(), initCbMpc(), initCbMpc()]);

  // DKG
  console.log("  Running 3-party DKG...");
  const transports = createMockNetwork(3);
  const curves = [mpc0.createCurve(NID_secp256k1), mpc1.createCurve(NID_secp256k1), mpc2.createCurve(NID_secp256k1)];
  const [key0, key1, key2] = await Promise.all([
    mpc0.ecKeyMpDkg(transports[0], 3, 0, names, curves[0]),
    mpc1.ecKeyMpDkg(transports[1], 3, 1, names, curves[1]),
    mpc2.ecKeyMpDkg(transports[2], 3, 2, names, curves[2]),
  ]);
  curves.forEach((c, i) => [mpc0, mpc1, mpc2][i].freeCurve(c));

  const info0 = mpc0.ecKeyMpInfo(key0);
  console.log(`  Public key: ${hexEncode(info0.publicKey).slice(0, 32)}...`);

  // Serialize all shares
  console.log("  Serializing all 3 key shares...");
  const allParts = [
    mpc0.serializeEcKeyMp(key0),
    mpc1.serializeEcKeyMp(key1),
    mpc2.serializeEcKeyMp(key2),
  ];
  for (let i = 0; i < 3; i++) {
    console.log(`  Party ${i}: ${allParts[i].length} parts, total ${allParts[i].reduce((s, p) => s + p.length, 0)} bytes`);
  }

  // Deserialize into fresh instances
  console.log("  Deserializing key shares...");
  const [mpc3, mpc4, mpc5] = await Promise.all([initCbMpc(), initCbMpc(), initCbMpc()]);
  const restored0 = mpc3.deserializeEcKeyMp(allParts[0]);
  const restored1 = mpc4.deserializeEcKeyMp(allParts[1]);
  const restored2 = mpc5.deserializeEcKeyMp(allParts[2]);

  const restoredInfo = mpc3.ecKeyMpInfo(restored0);
  console.log(`  Restored public key matches: ${hexEncode(info0.publicKey) === hexEncode(restoredInfo.publicKey)}`);
  console.log(`  Restored party name: ${restoredInfo.partyName}`);

  // Sign with restored keys (ECDSA MP)
  console.log("  Signing with restored keys (ECDSA MP)...");
  const msgHash = await sha256(new TextEncoder().encode("MP serialization test"));
  const signTransports = createMockNetwork(3);

  const [sig0, sig1, sig2] = await Promise.all([
    mpc3.ecdsaMpSign(signTransports[0], 3, 0, names, restored0, msgHash, 0),
    mpc4.ecdsaMpSign(signTransports[1], 3, 1, names, restored1, msgHash, 0),
    mpc5.ecdsaMpSign(signTransports[2], 3, 2, names, restored2, msgHash, 0),
  ]);
  // Party 0 is the sig receiver
  const valid = mpc3.verifyDer(NID_secp256k1, restoredInfo.publicKey, msgHash, sig0);
  console.log(`  Signature valid: ${valid}`);

  // Cleanup
  mpc0.freeEcKeyMp(key0);
  mpc1.freeEcKeyMp(key1);
  mpc2.freeEcKeyMp(key2);
  mpc3.freeEcKeyMp(restored0);
  mpc4.freeEcKeyMp(restored1);
  mpc5.freeEcKeyMp(restored2);
  console.log();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log("=== Key Serialization Demo ===\n");

  await demoEcdsa2p();
  await demoEcKey2p();
  await demoEcKeyMp();

  console.log("=== All serialization demos complete ===");
}

main().catch(console.error);
