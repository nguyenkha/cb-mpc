/**
 * ECDSA Multi-Party Computation Demo
 *
 * Demonstrates N-party ECDSA with 3 parties:
 *   1. Multi-party Distributed Key Generation
 *   2. Multi-party Collaborative Signing
 *   3. Key Refresh
 *
 * All parties run concurrently through an in-memory mock transport.
 *
 * IMPORTANT: Each concurrent MPC party must use its own CbMpc instance
 * (separate WASM module) because Emscripten ASYNCIFY only supports one
 * suspended async call stack per module at a time.
 */

import { initCbMpc, CbMpc, NID_secp256k1 } from "../dist/index";
import type { EcKeyMpHandle, PointHandle } from "../dist/index";
import { createMockNetwork } from "./mock-transport";

const N_PARTIES = 3;
const PARTY_NAMES = ["party_0", "party_1", "party_2"];

async function main() {
  console.log("=== ECDSA Multi-Party Computation Demo ===\n");
  console.log(`Parties: ${N_PARTIES} (${PARTY_NAMES.join(", ")})\n`);

  // Each party needs its own WASM module instance for concurrent execution.
  const mpcs = await Promise.all(
    Array.from({ length: N_PARTIES }, () => initCbMpc()),
  );

  // Create a curve handle (can use any instance for synchronous ops)
  const curve = mpcs[0].createCurve(NID_secp256k1);

  // --- Step 1: Multi-party DKG ---
  console.log("1. Running Multi-party DKG...");
  const keys = await runMpDkg(mpcs);

  // All parties should have the same public key
  const infos = keys.map((k, i) => mpcs[i].ecKeyMpInfo(k));
  console.log(`   Public key: ${hexEncode(infos[0].publicKey)}`);
  const allSamePubKey = infos.every(
    (info) => hexEncode(info.publicKey) === hexEncode(infos[0].publicKey),
  );
  console.log(`   All parties agree on public key: ${allSamePubKey}`);

  for (let i = 0; i < N_PARTIES; i++) {
    console.log(`   Party ${i} (${infos[i].partyName}): x_share = ${hexEncode(infos[i].xShare).slice(0, 16)}...`);
  }
  console.log();

  // --- Step 2: Multi-party Signing ---
  console.log("2. Running Multi-party Signing...");
  const message = new TextEncoder().encode("Multi-party MPC signing demo");
  const messageHash = await sha256(message);
  console.log(`   Message hash: ${hexEncode(messageHash)}`);

  // Party 0 is the signature receiver
  const sigReceiver = 0;
  const signature = await runMpSign(mpcs, keys, messageHash, sigReceiver);
  console.log(`   Signature (${signature.length} bytes): ${hexEncode(signature)}`);

  // Verify the signature using the public key
  const valid = mpcs[0].verifyDer(NID_secp256k1, infos[0].publicKey, messageHash, signature);
  console.log(`   Signature valid: ${valid}`);
  console.log();

  // --- Step 3: Key Refresh ---
  console.log("3. Running Multi-party Key Refresh...");
  const newKeys = await runMpRefresh(mpcs, keys);
  const newInfos = newKeys.map((k, i) => mpcs[i].ecKeyMpInfo(k));

  console.log(`   New public key: ${hexEncode(newInfos[0].publicKey)}`);
  console.log(`   Public key unchanged: ${hexEncode(infos[0].publicKey) === hexEncode(newInfos[0].publicKey)}`);

  // Verify shares changed
  for (let i = 0; i < N_PARTIES; i++) {
    const changed = hexEncode(infos[i].xShare) !== hexEncode(newInfos[i].xShare);
    console.log(`   Party ${i} share changed: ${changed}`);
  }
  console.log();

  // --- Step 4: Sign with refreshed keys ---
  console.log("4. Signing with refreshed keys...");
  const message2 = new TextEncoder().encode("Signed after refresh");
  const messageHash2 = await sha256(message2);

  const signature2 = await runMpSign(mpcs, newKeys, messageHash2, sigReceiver);
  const valid2 = mpcs[0].verifyDer(NID_secp256k1, newInfos[0].publicKey, messageHash2, signature2);
  console.log(`   Signature valid: ${valid2}`);
  console.log();

  // --- Step 5: Key Serialization ---
  console.log("5. Key serialization round-trip...");
  const serialized = mpcs[0].serializeEcKeyMp(keys[0]);
  console.log(`   Serialized to ${serialized.length} parts`);

  const deserialized = mpcs[0].deserializeEcKeyMp(serialized);
  const deserInfo = mpcs[0].ecKeyMpInfo(deserialized);
  console.log(`   Deserialized party name: ${deserInfo.partyName}`);
  console.log(`   Public key matches: ${hexEncode(deserInfo.publicKey) === hexEncode(infos[0].publicKey)}`);
  mpcs[0].freeEcKeyMp(deserialized);
  console.log();

  // --- Step 6: Reconstruct private key from shares ---
  console.log("6. Reconstructing private key from shares...");
  const privateKey = mpcs[0].reconstructKey(NID_secp256k1, newInfos.map((info) => info.xShare));
  console.log(`   Private key (${privateKey.length} bytes): ${hexEncode(privateKey).slice(0, 16)}...`);

  // Verify: x * G should equal the public key Q
  const derivedQ = mpcs[0].mulGenerator(curve, privateKey);
  const derivedPub = toSec1Uncompressed(mpcs[0], derivedQ, 32);
  const keysMatch = hexEncode(derivedPub) === hexEncode(newInfos[0].publicKey);
  console.log(`   x * G == Q: ${keysMatch}`);
  mpcs[0].freePoint(derivedQ);
  console.log();

  // --- Cleanup ---
  for (let i = 0; i < N_PARTIES; i++) {
    mpcs[i].freeEcKeyMp(keys[i]);
    mpcs[i].freeEcKeyMp(newKeys[i]);
  }
  mpcs[0].freeCurve(curve);

  console.log("=== Demo complete ===");
}

/** Run N-party DKG. Each party uses its own CbMpc instance. */
async function runMpDkg(mpcs: CbMpc[]): Promise<EcKeyMpHandle[]> {
  const transports = createMockNetwork(N_PARTIES);
  // Each party needs its own curve handle from its own WASM instance
  const curves = mpcs.map((mpc) => mpc.createCurve(NID_secp256k1));

  const keys = await Promise.all(
    mpcs.map((mpc, i) =>
      mpc.ecKeyMpDkg(transports[i], N_PARTIES, i, PARTY_NAMES, curves[i]),
    ),
  );

  // Free per-party curve handles
  curves.forEach((c, i) => mpcs[i].freeCurve(c));

  return keys;
}

/** Run N-party signing. Returns the signature. */
async function runMpSign(
  mpcs: CbMpc[],
  keys: EcKeyMpHandle[],
  messageHash: Uint8Array,
  sigReceiver: number,
): Promise<Uint8Array> {
  const transports = createMockNetwork(N_PARTIES);

  const results = await Promise.all(
    mpcs.map((mpc, i) =>
      mpc.ecdsaMpSign(transports[i], N_PARTIES, i, PARTY_NAMES, keys[i], messageHash, sigReceiver),
    ),
  );

  // The signature receiver gets the non-empty result.
  const sig = results.find((r) => r.length > 0);
  if (!sig) throw new Error("No party received a signature");
  return sig;
}

/** Run N-party key refresh. */
async function runMpRefresh(mpcs: CbMpc[], keys: EcKeyMpHandle[]): Promise<EcKeyMpHandle[]> {
  const transports = createMockNetwork(N_PARTIES);
  const sessionId = crypto.getRandomValues(new Uint8Array(32));

  const newKeys = await Promise.all(
    mpcs.map((mpc, i) =>
      mpc.ecKeyMpRefresh(transports[i], N_PARTIES, i, PARTY_NAMES, keys[i], sessionId),
    ),
  );

  return newKeys;
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

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", data as unknown as ArrayBuffer);
  return new Uint8Array(buf);
}

main().catch(console.error);
