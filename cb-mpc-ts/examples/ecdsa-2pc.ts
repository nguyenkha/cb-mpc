/**
 * ECDSA Two-Party Computation Demo
 *
 * Demonstrates the full lifecycle of two-party ECDSA:
 *   1. Distributed Key Generation (DKG)
 *   2. Collaborative Signing
 *   3. Key Refresh (re-sharing without changing the public key)
 *   4. Signing with refreshed keys
 *
 * Both parties run concurrently and communicate through an in-memory
 * mock transport. In production, replace with WebSocket or HTTP transport.
 *
 * IMPORTANT: Each concurrent MPC party must use its own CbMpc instance
 * (separate WASM module) because Emscripten ASYNCIFY only supports one
 * suspended async call stack per module at a time.
 */

import { initCbMpc, CbMpc, NID_secp256k1 } from "../dist/index";
import type { Ecdsa2pKeyHandle } from "../dist/index";
import { createMockNetwork } from "./mock-transport";

const PARTY_NAMES: [string, string] = ["alice", "bob"];

async function main() {
  console.log("=== ECDSA Two-Party Computation Demo ===\n");

  // Each party needs its own WASM module instance for concurrent execution.
  // ASYNCIFY only supports one suspended call stack per WASM module.
  const [mpc0, mpc1] = await Promise.all([initCbMpc(), initCbMpc()]);

  // --- Step 1: Distributed Key Generation ---
  console.log("1. Running Distributed Key Generation (DKG)...");
  const { keys, publicKey } = await runDkg(mpc0, mpc1);
  console.log(`   Public key (${publicKey.length} bytes): ${hexEncode(publicKey)}`);
  console.log(`   Party 0 role index: ${mpc0.ecdsa2pKeyInfo(keys[0]).roleIndex}`);
  console.log(`   Party 1 role index: ${mpc1.ecdsa2pKeyInfo(keys[1]).roleIndex}`);
  console.log();

  // --- Step 2: Signing ---
  console.log("2. Signing a message...");
  const message = new TextEncoder().encode("Hello, MPC world!");
  const messageHash = await sha256(message);
  console.log(`   Message hash: ${hexEncode(messageHash)}`);

  const signatures = await runSign(mpc0, mpc1, keys, messageHash);
  console.log(`   Signature (${signatures[0].length} bytes): ${hexEncode(signatures[0])}`);

  // Verify the signature
  const valid = mpc0.verifyDer(NID_secp256k1, publicKey, messageHash, signatures[0]);
  console.log(`   Signature valid: ${valid}`);
  console.log();

  // --- Step 3: Key Refresh ---
  console.log("3. Refreshing keys (re-sharing)...");
  const { newKeys, newPublicKey } = await runRefresh(mpc0, mpc1, keys);
  console.log(`   New public key: ${hexEncode(newPublicKey)}`);
  console.log(`   Public key unchanged: ${hexEncode(publicKey) === hexEncode(newPublicKey)}`);

  // Verify old shares differ from new shares
  const oldInfo = mpc0.ecdsa2pKeyInfo(keys[0]);
  const newInfo = mpc0.ecdsa2pKeyInfo(newKeys[0]);
  console.log(`   Secret share changed: ${hexEncode(oldInfo.xShare) !== hexEncode(newInfo.xShare)}`);
  console.log();

  // --- Step 4: Signing with refreshed keys ---
  console.log("4. Signing with refreshed keys...");
  const message2 = new TextEncoder().encode("Refreshed key signing!");
  const messageHash2 = await sha256(message2);

  const signatures2 = await runSign(mpc0, mpc1, newKeys, messageHash2);
  console.log(`   Signature: ${hexEncode(signatures2[0])}`);

  const valid2 = mpc0.verifyDer(NID_secp256k1, newPublicKey, messageHash2, signatures2[0]);
  console.log(`   Signature valid: ${valid2}`);
  console.log();

  // --- Step 5: Reconstruct private key from shares ---
  console.log("5. Reconstructing private key from shares...");
  const info0 = mpc0.ecdsa2pKeyInfo(newKeys[0]);
  const info1 = mpc1.ecdsa2pKeyInfo(newKeys[1]);
  const privateKey = mpc0.reconstructKey(NID_secp256k1, [info0.xShare, info1.xShare]);
  console.log(`   Private key (${privateKey.length} bytes): ${hexEncode(privateKey).slice(0, 16)}...`);

  // Verify: x * G should equal the public key Q
  const curve = mpc0.createCurve(NID_secp256k1);
  const derivedQ = mpc0.mulGenerator(curve, privateKey);
  const derivedPub = toSec1Uncompressed(mpc0, derivedQ, 32);
  const keysMatch = hexEncode(derivedPub) === hexEncode(info0.publicKey);
  console.log(`   x * G == Q: ${keysMatch}`);
  mpc0.freePoint(derivedQ);
  mpc0.freeCurve(curve);
  console.log();

  // --- Cleanup ---
  mpc0.freeEcdsa2pKey(keys[0]);
  mpc1.freeEcdsa2pKey(keys[1]);
  mpc0.freeEcdsa2pKey(newKeys[0]);
  mpc1.freeEcdsa2pKey(newKeys[1]);

  console.log("=== Demo complete ===");
}

/** Run two-party DKG, returning key handles for both parties. */
async function runDkg(mpc0: CbMpc, mpc1: CbMpc) {
  const transports = createMockNetwork(2);

  const [key0, key1] = await Promise.all([
    mpc0.ecdsa2pDkg(transports[0], 0, PARTY_NAMES, NID_secp256k1),
    mpc1.ecdsa2pDkg(transports[1], 1, PARTY_NAMES, NID_secp256k1),
  ]);

  const keys: [Ecdsa2pKeyHandle, Ecdsa2pKeyHandle] = [key0, key1];
  const publicKey = mpc0.ecdsa2pKeyInfo(key0).publicKey;

  return { keys, publicKey };
}

/** Run two-party signing, returning signatures for both parties. */
async function runSign(
  mpc0: CbMpc,
  mpc1: CbMpc,
  keys: [Ecdsa2pKeyHandle, Ecdsa2pKeyHandle],
  messageHash: Uint8Array,
) {
  const transports = createMockNetwork(2);
  const sessionId = crypto.getRandomValues(new Uint8Array(32));

  const [sigs0, sigs1] = await Promise.all([
    mpc0.ecdsa2pSign(transports[0], 0, PARTY_NAMES, keys[0], sessionId, [messageHash]),
    mpc1.ecdsa2pSign(transports[1], 1, PARTY_NAMES, keys[1], sessionId, [messageHash]),
  ]);

  // One party receives the signature; return whichever is non-empty.
  const sig = sigs0[0].length > 0 ? sigs0 : sigs1;
  return sig;
}

/** Run two-party key refresh, returning new key handles. */
async function runRefresh(
  mpc0: CbMpc,
  mpc1: CbMpc,
  keys: [Ecdsa2pKeyHandle, Ecdsa2pKeyHandle],
) {
  const transports = createMockNetwork(2);

  const [newKey0, newKey1] = await Promise.all([
    mpc0.ecdsa2pRefresh(transports[0], 0, PARTY_NAMES, keys[0]),
    mpc1.ecdsa2pRefresh(transports[1], 1, PARTY_NAMES, keys[1]),
  ]);

  const newKeys: [Ecdsa2pKeyHandle, Ecdsa2pKeyHandle] = [newKey0, newKey1];
  const newPublicKey = mpc0.ecdsa2pKeyInfo(newKey0).publicKey;

  return { newKeys, newPublicKey };
}

// --- Utility functions ---

/** Build SEC1 uncompressed format (04 || x || y) from a point handle. */
function toSec1Uncompressed(mpc: CbMpc, point: import("cb-mpc").PointHandle, coordSize: number): Uint8Array {
  const x = mpc.pointGetX(point);
  const y = mpc.pointGetY(point);
  const result = new Uint8Array(1 + coordSize * 2);
  result[0] = 0x04;
  result.set(x, 1 + coordSize - x.length);
  result.set(y, 1 + coordSize + coordSize - y.length);
  return result;
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", data as unknown as ArrayBuffer);
  return new Uint8Array(buf);
}

main().catch(console.error);
