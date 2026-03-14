/**
 * EdDSA Two-Party Computation Demo
 *
 * Demonstrates 2-party EdDSA (Ed25519) using Schnorr 2P protocol:
 *   1. Two-party Distributed Key Generation
 *   2. Two-party Collaborative Signing
 *   3. Signature Verification (using Node.js crypto)
 *
 * Both parties run concurrently through an in-memory mock transport.
 *
 * IMPORTANT: Each concurrent MPC party must use its own CbMpc instance
 * (separate WASM module) because Emscripten ASYNCIFY only supports one
 * suspended async call stack per module at a time.
 */

import { initCbMpc, CbMpc, NID_ED25519 } from "../dist/index";
import type { PointHandle } from "../dist/index";
import { createMockNetwork } from "./mock-transport";

const PARTY_NAMES: [string, string] = ["alice", "bob"];

async function main() {
  console.log("=== EdDSA Two-Party Computation Demo ===\n");

  // Each party needs its own WASM module instance for concurrent execution.
  const [mpc0, mpc1] = await Promise.all([initCbMpc(), initCbMpc()]);

  // --- Step 1: Two-party DKG ---
  console.log("1. Running Two-party DKG (Ed25519)...");
  const transports0 = createMockNetwork(2);

  const [key0, key1] = await Promise.all([
    mpc0.ecKey2pDkg(transports0[0], 0, PARTY_NAMES, NID_ED25519),
    mpc1.ecKey2pDkg(transports0[1], 1, PARTY_NAMES, NID_ED25519),
  ]);

  const info0 = mpc0.ecKey2pInfo(key0);
  const info1 = mpc1.ecKey2pInfo(key1);
  console.log(`   Public key (SEC1): ${hexEncode(info0.publicKey)}`);
  console.log(`   Public keys match: ${hexEncode(info0.publicKey) === hexEncode(info1.publicKey)}`);
  console.log(`   Alice x_share: ${hexEncode(info0.xShare).slice(0, 16)}...`);
  console.log(`   Bob   x_share: ${hexEncode(info1.xShare).slice(0, 16)}...`);
  console.log();

  // --- Step 2: Two-party Signing ---
  console.log("2. Running Two-party EdDSA Signing (Schnorr 2P)...");
  const message = new TextEncoder().encode("EdDSA two-party signing demo");
  console.log(`   Message: "${new TextDecoder().decode(message)}"`);

  const transports1 = createMockNetwork(2);
  const [sig0, sig1] = await Promise.all([
    mpc0.schnorr2pEddsaSign(transports1[0], 0, PARTY_NAMES, key0, message),
    mpc1.schnorr2pEddsaSign(transports1[1], 1, PARTY_NAMES, key1, message),
  ]);

  // Party 0 (p1) receives the signature
  const signature = sig0.length > 0 ? sig0 : sig1;
  console.log(`   Signature (${signature.length} bytes): ${hexEncode(signature)}`);
  console.log();

  // --- Step 3: Verify signature using Node.js crypto ---
  console.log("3. Verifying signature with Node.js crypto...");
  const ed25519PubKey = sec1ToEd25519PublicKey(info0.publicKey);
  console.log(`   Ed25519 public key (${ed25519PubKey.length} bytes): ${hexEncode(ed25519PubKey)}`);

  const valid = await verifyEd25519(ed25519PubKey, message, signature);
  console.log(`   Signature valid: ${valid}`);
  console.log();

  // --- Step 4: Reconstruct private key from shares ---
  console.log("4. Reconstructing private key from shares...");
  const privateKey = mpc0.reconstructKey(NID_ED25519, [info0.xShare, info1.xShare]);
  console.log(`   Private key (${privateKey.length} bytes): ${hexEncode(privateKey).slice(0, 16)}...`);

  // Verify: x * G should equal the public key Q
  const curve = mpc0.createCurve(NID_ED25519);
  const derivedQ = mpc0.mulGenerator(curve, privateKey);
  const derivedPub = toSec1Uncompressed(mpc0, derivedQ, 32);
  const keysMatch = hexEncode(derivedPub) === hexEncode(info0.publicKey);
  console.log(`   x * G == Q: ${keysMatch}`);
  mpc0.freePoint(derivedQ);
  mpc0.freeCurve(curve);
  console.log();

  // --- Cleanup ---
  mpc0.freeEcKey2p(key0);
  mpc1.freeEcKey2p(key1);

  console.log("=== Demo complete ===");
}

/**
 * Convert SEC1 uncompressed public key (04 || x || y) to Ed25519
 * 32-byte compressed format (little-endian y with sign bit of x in MSB).
 */
function sec1ToEd25519PublicKey(sec1: Uint8Array): Uint8Array {
  if (sec1[0] !== 0x04 || sec1.length !== 65) {
    throw new Error(`Expected 65-byte SEC1 uncompressed key, got ${sec1.length} bytes`);
  }
  const x = sec1.slice(1, 33);
  const y = sec1.slice(33, 65);

  // Ed25519 encoding: little-endian y coordinate, MSB = sign bit of x
  const pub = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    pub[i] = y[31 - i]; // reverse y to little-endian
  }
  // Set high bit to the sign of x (x[31] & 1 is the least significant bit of x, big-endian)
  pub[31] |= (x[31] & 1) << 7;

  return pub;
}

/** Verify an Ed25519 signature using Node.js crypto. */
async function verifyEd25519(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const crypto = await import("node:crypto");
  const keyObj = crypto.createPublicKey({
    key: Buffer.concat([
      // Ed25519 PKCS8/SPKI DER prefix for 32-byte key
      Buffer.from("302a300506032b6570032100", "hex"),
      publicKey,
    ]),
    format: "der",
    type: "spki",
  });
  return crypto.verify(null, message, keyObj, signature);
}

// --- Utilities ---

/** Build SEC1 uncompressed format (04 || x || y) from a point handle. */
function toSec1Uncompressed(mpc: CbMpc, point: PointHandle, coordSize: number): Uint8Array {
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

main().catch(console.error);
