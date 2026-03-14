/**
 * EdDSA Multi-Party Computation Demo
 *
 * Demonstrates N-party EdDSA (Ed25519) with 3 parties:
 *   1. Multi-party Distributed Key Generation
 *   2. Multi-party Collaborative Signing
 *   3. Signature Verification (using Node.js crypto)
 *
 * All parties run concurrently through an in-memory mock transport.
 *
 * IMPORTANT: Each concurrent MPC party must use its own CbMpc instance
 * (separate WASM module) because Emscripten ASYNCIFY only supports one
 * suspended async call stack per module at a time.
 */

import { initCbMpc, CbMpc, NID_ED25519 } from "../dist/index";
import type { EcKeyMpHandle, PointHandle } from "../dist/index";
import { createMockNetwork } from "./mock-transport";

const N_PARTIES = 3;
const PARTY_NAMES = ["party_0", "party_1", "party_2"];

async function main() {
  console.log("=== EdDSA Multi-Party Computation Demo ===\n");
  console.log(`Parties: ${N_PARTIES} (${PARTY_NAMES.join(", ")})\n`);

  // Each party needs its own WASM module instance for concurrent execution.
  const mpcs = await Promise.all(
    Array.from({ length: N_PARTIES }, () => initCbMpc()),
  );

  // --- Step 1: Multi-party DKG ---
  console.log("1. Running Multi-party DKG (Ed25519)...");
  const keys = await runMpDkg(mpcs);

  const infos = keys.map((k, i) => mpcs[i].ecKeyMpInfo(k));
  console.log(`   Public key (SEC1): ${hexEncode(infos[0].publicKey)}`);
  const allSamePubKey = infos.every(
    (info) => hexEncode(info.publicKey) === hexEncode(infos[0].publicKey),
  );
  console.log(`   All parties agree on public key: ${allSamePubKey}`);

  for (let i = 0; i < N_PARTIES; i++) {
    console.log(`   Party ${i} (${infos[i].partyName}): x_share = ${hexEncode(infos[i].xShare).slice(0, 16)}...`);
  }
  console.log();

  // --- Step 2: Multi-party Signing ---
  console.log("2. Running Multi-party EdDSA Signing...");
  const message = new TextEncoder().encode("EdDSA multi-party signing demo");
  console.log(`   Message: "${new TextDecoder().decode(message)}"`);

  // Party 0 is the signature receiver
  const sigReceiver = 0;
  const signature = await runMpSign(mpcs, keys, message, sigReceiver);
  console.log(`   Signature (${signature.length} bytes): ${hexEncode(signature)}`);
  console.log();

  // --- Step 3: Verify signature using Node.js crypto ---
  console.log("3. Verifying signature with Node.js crypto...");
  const ed25519PubKey = sec1ToEd25519PublicKey(infos[0].publicKey);
  console.log(`   Ed25519 public key (${ed25519PubKey.length} bytes): ${hexEncode(ed25519PubKey)}`);

  const valid = await verifyEd25519(ed25519PubKey, message, signature);
  console.log(`   Signature valid: ${valid}`);
  console.log();

  // --- Step 4: Reconstruct private key from shares ---
  console.log("4. Reconstructing private key from shares...");
  const privateKey = mpcs[0].reconstructKey(NID_ED25519, infos.map((info) => info.xShare));
  console.log(`   Private key (${privateKey.length} bytes): ${hexEncode(privateKey).slice(0, 16)}...`);

  // Verify: x * G should equal the public key Q
  const curve = mpcs[0].createCurve(NID_ED25519);
  const derivedQ = mpcs[0].mulGenerator(curve, privateKey);
  const derivedPub = toSec1Uncompressed(mpcs[0], derivedQ, 32);
  const keysMatch = hexEncode(derivedPub) === hexEncode(infos[0].publicKey);
  console.log(`   x * G == Q: ${keysMatch}`);
  mpcs[0].freePoint(derivedQ);
  mpcs[0].freeCurve(curve);
  console.log();

  // --- Cleanup ---
  for (let i = 0; i < N_PARTIES; i++) {
    mpcs[i].freeEcKeyMp(keys[i]);
  }

  console.log("=== Demo complete ===");
}

/** Run N-party DKG with Ed25519 curve. */
async function runMpDkg(mpcs: CbMpc[]): Promise<EcKeyMpHandle[]> {
  const transports = createMockNetwork(N_PARTIES);
  const curves = mpcs.map((mpc) => mpc.createCurve(NID_ED25519));

  const keys = await Promise.all(
    mpcs.map((mpc, i) =>
      mpc.ecKeyMpDkg(transports[i], N_PARTIES, i, PARTY_NAMES, curves[i]),
    ),
  );

  curves.forEach((c, i) => mpcs[i].freeCurve(c));
  return keys;
}

/** Run N-party EdDSA signing. Returns the signature. */
async function runMpSign(
  mpcs: CbMpc[],
  keys: EcKeyMpHandle[],
  message: Uint8Array,
  sigReceiver: number,
): Promise<Uint8Array> {
  const transports = createMockNetwork(N_PARTIES);

  const results = await Promise.all(
    mpcs.map((mpc, i) =>
      mpc.eddsaMpSign(transports[i], N_PARTIES, i, PARTY_NAMES, keys[i], message, sigReceiver),
    ),
  );

  const sig = results.find((r) => r.length > 0);
  if (!sig) throw new Error("No party received a signature");
  return sig;
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
