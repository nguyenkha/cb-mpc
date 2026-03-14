/**
 * ECDSA Multi-Party Computation Demo
 *
 * Demonstrates N-party ECDSA with 3 parties:
 *   1. Multi-party Distributed Key Generation
 *   2. Multi-party Collaborative Signing
 *   3. Key Refresh
 *
 * All parties run concurrently through an in-memory mock transport.
 */

import { initCbMpc, CbMpc, NID_secp256k1 } from "@aspect-build/cb-mpc-wasm";
import type { CurveHandle, EcKeyMpHandle } from "@aspect-build/cb-mpc-wasm";
import { createMockNetwork } from "./mock-transport";

const N_PARTIES = 3;
const PARTY_NAMES = ["party_0", "party_1", "party_2"];

async function main() {
  console.log("=== ECDSA Multi-Party Computation Demo ===\n");
  console.log(`Parties: ${N_PARTIES} (${PARTY_NAMES.join(", ")})\n`);

  const mpc = await initCbMpc();

  // Create a curve handle for DKG
  const curve = mpc.createCurve(NID_secp256k1);

  // --- Step 1: Multi-party DKG ---
  console.log("1. Running Multi-party DKG...");
  const keys = await runMpDkg(mpc, curve);

  // All parties should have the same public key
  const infos = keys.map((k) => mpc.ecKeyMpInfo(k));
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
  const signature = await runMpSign(mpc, keys, messageHash, sigReceiver);
  console.log(`   Signature (${signature.length} bytes): ${hexEncode(signature)}`);

  // Verify the signature using the public key
  const valid = mpc.verifyDer(NID_secp256k1, infos[0].publicKey, messageHash, signature);
  console.log(`   Signature valid: ${valid}`);
  console.log();

  // --- Step 3: Key Refresh ---
  console.log("3. Running Multi-party Key Refresh...");
  const newKeys = await runMpRefresh(mpc, keys);
  const newInfos = newKeys.map((k) => mpc.ecKeyMpInfo(k));

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

  const signature2 = await runMpSign(mpc, newKeys, messageHash2, sigReceiver);
  const valid2 = mpc.verifyDer(NID_secp256k1, newInfos[0].publicKey, messageHash2, signature2);
  console.log(`   Signature valid: ${valid2}`);
  console.log();

  // --- Step 5: Key Serialization ---
  console.log("5. Key serialization round-trip...");
  const serialized = mpc.serializeEcKeyMp(keys[0]);
  console.log(`   Serialized to ${serialized.length} parts`);

  const deserialized = mpc.deserializeEcKeyMp(serialized);
  const deserInfo = mpc.ecKeyMpInfo(deserialized);
  console.log(`   Deserialized party name: ${deserInfo.partyName}`);
  console.log(`   Public key matches: ${hexEncode(deserInfo.publicKey) === hexEncode(infos[0].publicKey)}`);
  mpc.freeEcKeyMp(deserialized);
  console.log();

  // --- Cleanup ---
  for (const k of keys) mpc.freeEcKeyMp(k);
  for (const k of newKeys) mpc.freeEcKeyMp(k);
  mpc.freeCurve(curve);

  console.log("=== Demo complete ===");
}

/** Run N-party DKG. */
async function runMpDkg(mpc: CbMpc, curve: CurveHandle): Promise<EcKeyMpHandle[]> {
  const transports = createMockNetwork(N_PARTIES);

  const keys = await Promise.all(
    Array.from({ length: N_PARTIES }, (_, i) =>
      mpc.ecKeyMpDkg(transports[i], N_PARTIES, i, PARTY_NAMES, curve),
    ),
  );

  return keys;
}

/** Run N-party signing. Returns the signature. */
async function runMpSign(
  mpc: CbMpc,
  keys: EcKeyMpHandle[],
  messageHash: Uint8Array,
  sigReceiver: number,
): Promise<Uint8Array> {
  const transports = createMockNetwork(N_PARTIES);

  const results = await Promise.all(
    Array.from({ length: N_PARTIES }, (_, i) =>
      mpc.ecdsaMpSign(transports[i], N_PARTIES, i, PARTY_NAMES, keys[i], messageHash, sigReceiver),
    ),
  );

  // The signature receiver gets the non-empty result.
  const sig = results.find((r) => r.length > 0);
  if (!sig) throw new Error("No party received a signature");
  return sig;
}

/** Run N-party key refresh. */
async function runMpRefresh(mpc: CbMpc, keys: EcKeyMpHandle[]): Promise<EcKeyMpHandle[]> {
  const transports = createMockNetwork(N_PARTIES);
  const sessionId = crypto.getRandomValues(new Uint8Array(32));

  const newKeys = await Promise.all(
    Array.from({ length: N_PARTIES }, (_, i) =>
      mpc.ecKeyMpRefresh(transports[i], N_PARTIES, i, PARTY_NAMES, keys[i], sessionId),
    ),
  );

  return newKeys;
}

// --- Utilities ---

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
