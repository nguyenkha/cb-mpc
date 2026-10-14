/**
 * PVE (Publicly Verifiable Encryption) Backup Demo
 *
 * Backs up party 1's key shares (ECDSA-2P on secp256k1 and EC-key-2P on
 * Ed25519) to a recipient key, then:
 *   1. verifies the backup against the public share points, without decrypting
 *   2. checks that a wrong label or wrong point fails verification
 *   3. decrypts and compares with the original shares
 *
 * Run with the WASM backend (default) or the native one:
 *   bun run examples/pve-backup.ts
 *   CBMPC_BACKEND=native bun run examples/pve-backup.ts
 *
 * The DKG that produces the shares always runs on WASM (the native backend is
 * synchronous, so two in-process parties cannot talk to each other); the PVE
 * calls run on the selected backend.
 *
 * Exits non-zero on any mismatch, so it doubles as a test.
 */

import { initCbMpc, initCbMpcBunFfi, CbMpc, NID_secp256k1, NID_ED25519 } from "../dist/index";
import { createMockNetwork } from "./mock-transport";

const PARTY_NAMES: [string, string] = ["client", "server"];

function initPveBackend(): Promise<CbMpc> {
  return process.env.CBMPC_BACKEND === "native" ? initCbMpcBunFfi() : initCbMpc();
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

function check(ok: boolean, what: string): void {
  console.log(`   ${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) process.exitCode = 1;
}

/** Public share point x*G in the encoding pveBatchVerify expects. */
function sharePoint(mpc: CbMpc, curveCode: number, x: Uint8Array): Uint8Array {
  const curve = mpc.createCurve(curveCode);
  const point = mpc.mulGenerator(curve, x);
  const bytes = mpc.pointToBytes(point);
  mpc.freePoint(point);
  mpc.freeCurve(curve);
  return bytes;
}

function roundTrip(mpc: CbMpc, curveCode: number, name: string, xShare: Uint8Array): void {
  console.log(`\n${name}:`);
  const { ek, dk } = mpc.pveGenerateKeypair();
  const label = new TextEncoder().encode("key-share-backup:demo");
  const Q = sharePoint(mpc, curveCode, xShare);

  const ct = mpc.pveBatchEncrypt(curveCode, ek, label, [xShare]);
  console.log(`   ciphertext ${ct.length} bytes`);

  check(mpc.pveBatchVerify(curveCode, ek, ct, [Q], label), "verifies against Q");
  check(!mpc.pveBatchVerify(curveCode, ek, ct, [Q], new TextEncoder().encode("other")), "wrong label rejected");
  const otherQ = sharePoint(mpc, curveCode, new Uint8Array(32).fill(7));
  check(!mpc.pveBatchVerify(curveCode, ek, ct, [otherQ], label), "wrong Q rejected");
  const otherEk = mpc.pveGenerateKeypair().ek;
  check(!mpc.pveBatchVerify(curveCode, otherEk, ct, [Q], label), "wrong ek rejected");

  const [x] = mpc.pveBatchDecrypt(curveCode, dk, ek, ct, label);
  // Decrypted scalar may drop leading zero bytes; compare as integers.
  check(BigInt("0x" + (hex(x) || "0")) === BigInt("0x" + (hex(xShare) || "0")), "decrypts to the original share");
}

async function main() {
  console.log(`=== PVE backup demo (${process.env.CBMPC_BACKEND === "native" ? "native" : "wasm"}) ===`);
  const [mpc0, mpc1] = await Promise.all([initCbMpc(), initCbMpc()]);
  const pve = await initPveBackend();

  let net = createMockNetwork(2);
  const [, ecdsaKey1] = await Promise.all([
    mpc0.ecdsa2pDkg(net[0], 0, PARTY_NAMES, NID_secp256k1),
    mpc1.ecdsa2pDkg(net[1], 1, PARTY_NAMES, NID_secp256k1),
  ]);
  roundTrip(pve, NID_secp256k1, "ECDSA-2P secp256k1, party 1 share", mpc1.ecdsa2pKeyInfo(ecdsaKey1).xShare);

  net = createMockNetwork(2);
  const [, eddsaKey1] = await Promise.all([
    mpc0.ecKey2pDkg(net[0], 0, PARTY_NAMES, NID_ED25519),
    mpc1.ecKey2pDkg(net[1], 1, PARTY_NAMES, NID_ED25519),
  ]);
  roundTrip(pve, NID_ED25519, "EC-key-2P Ed25519, party 1 share", mpc1.ecKey2pInfo(eddsaKey1).xShare);

  console.log(process.exitCode ? "\nFAILED" : "\nAll checks passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
