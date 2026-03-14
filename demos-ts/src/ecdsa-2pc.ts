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
 */

import { initCbMpc, CbMpc, NID_secp256k1 } from "cb-mpc";
import type { Ecdsa2pKeyHandle } from "cb-mpc";
import { createMockNetwork } from "./mock-transport";

const PARTY_NAMES: [string, string] = ["alice", "bob"];

async function main() {
  console.log("=== ECDSA Two-Party Computation Demo ===\n");

  // Initialize the WASM module
  const mpc = await initCbMpc();

  // --- Step 1: Distributed Key Generation ---
  console.log("1. Running Distributed Key Generation (DKG)...");
  const { keys, publicKey } = await runDkg(mpc);
  console.log(`   Public key (${publicKey.length} bytes): ${hexEncode(publicKey)}`);
  console.log(`   Party 0 role index: ${mpc.ecdsa2pKeyInfo(keys[0]).roleIndex}`);
  console.log(`   Party 1 role index: ${mpc.ecdsa2pKeyInfo(keys[1]).roleIndex}`);
  console.log();

  // --- Step 2: Signing ---
  console.log("2. Signing a message...");
  const message = new TextEncoder().encode("Hello, MPC world!");
  const messageHash = await sha256(message);
  console.log(`   Message hash: ${hexEncode(messageHash)}`);

  const signatures = await runSign(mpc, keys, messageHash);
  console.log(`   Signature (${signatures[0].length} bytes): ${hexEncode(signatures[0])}`);

  // Verify the signature
  const valid = mpc.verifyDer(NID_secp256k1, publicKey, messageHash, signatures[0]);
  console.log(`   Signature valid: ${valid}`);
  console.log();

  // --- Step 3: Key Refresh ---
  console.log("3. Refreshing keys (re-sharing)...");
  const { newKeys, newPublicKey } = await runRefresh(mpc, keys);
  console.log(`   New public key: ${hexEncode(newPublicKey)}`);
  console.log(`   Public key unchanged: ${hexEncode(publicKey) === hexEncode(newPublicKey)}`);

  // Verify old shares differ from new shares
  const oldInfo = mpc.ecdsa2pKeyInfo(keys[0]);
  const newInfo = mpc.ecdsa2pKeyInfo(newKeys[0]);
  console.log(`   Secret share changed: ${hexEncode(oldInfo.xShare) !== hexEncode(newInfo.xShare)}`);
  console.log();

  // --- Step 4: Signing with refreshed keys ---
  console.log("4. Signing with refreshed keys...");
  const message2 = new TextEncoder().encode("Refreshed key signing!");
  const messageHash2 = await sha256(message2);

  const signatures2 = await runSign(mpc, newKeys, messageHash2);
  console.log(`   Signature: ${hexEncode(signatures2[0])}`);

  const valid2 = mpc.verifyDer(NID_secp256k1, newPublicKey, messageHash2, signatures2[0]);
  console.log(`   Signature valid: ${valid2}`);
  console.log();

  // --- Cleanup ---
  for (const k of keys) mpc.freeEcdsa2pKey(k);
  for (const k of newKeys) mpc.freeEcdsa2pKey(k);

  console.log("=== Demo complete ===");
}

/** Run two-party DKG, returning key handles for both parties. */
async function runDkg(mpc: CbMpc) {
  const transports = createMockNetwork(2);

  const [key0, key1] = await Promise.all([
    mpc.ecdsa2pDkg(transports[0], 0, PARTY_NAMES, NID_secp256k1),
    mpc.ecdsa2pDkg(transports[1], 1, PARTY_NAMES, NID_secp256k1),
  ]);

  const keys: [Ecdsa2pKeyHandle, Ecdsa2pKeyHandle] = [key0, key1];
  const publicKey = mpc.ecdsa2pKeyInfo(key0).publicKey;

  return { keys, publicKey };
}

/** Run two-party signing, returning signatures for both parties. */
async function runSign(
  mpc: CbMpc,
  keys: [Ecdsa2pKeyHandle, Ecdsa2pKeyHandle],
  messageHash: Uint8Array,
) {
  const transports = createMockNetwork(2);
  const sessionId = crypto.getRandomValues(new Uint8Array(32));

  const [sigs0, sigs1] = await Promise.all([
    mpc.ecdsa2pSign(transports[0], 0, PARTY_NAMES, keys[0], sessionId, [messageHash]),
    mpc.ecdsa2pSign(transports[1], 1, PARTY_NAMES, keys[1], sessionId, [messageHash]),
  ]);

  // One party receives the signature; return whichever is non-empty.
  const sig = sigs0[0].length > 0 ? sigs0 : sigs1;
  return sig;
}

/** Run two-party key refresh, returning new key handles. */
async function runRefresh(mpc: CbMpc, keys: [Ecdsa2pKeyHandle, Ecdsa2pKeyHandle]) {
  const transports = createMockNetwork(2);

  const [newKey0, newKey1] = await Promise.all([
    mpc.ecdsa2pRefresh(transports[0], 0, PARTY_NAMES, keys[0]),
    mpc.ecdsa2pRefresh(transports[1], 1, PARTY_NAMES, keys[1]),
  ]);

  const newKeys: [Ecdsa2pKeyHandle, Ecdsa2pKeyHandle] = [newKey0, newKey1];
  const newPublicKey = mpc.ecdsa2pKeyInfo(newKey0).publicKey;

  return { newKeys, newPublicKey };
}

// --- Utility functions ---

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const { createHash } = await import("crypto");
  return new Uint8Array(createHash("sha256").update(data).digest());
}

main().catch(console.error);
