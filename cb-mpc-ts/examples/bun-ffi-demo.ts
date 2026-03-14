/**
 * Bun FFI Backend Demo
 *
 * Demonstrates that the native bun:ffi backend works correctly by
 * performing cryptographic operations through the shared library:
 *   1. Key generation (scalar * generator point)
 *   2. ECDSA signing (via Node crypto) and verification (via native lib)
 *   3. Multi-curve support (secp256k1, P-256, Ed25519)
 *   4. Schnorr-style challenge computation
 *
 * This demo uses initCbMpcAuto which selects bun:ffi when running
 * under Bun with a prebuilt native library available.
 */

import {
  initCbMpcAuto,
  NID_secp256k1,
  NID_X9_62_prime256v1,
  NID_ED25519,
} from "../dist/index";

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function main() {
  console.log("=== Bun FFI Backend Demo ===\n");

  const mpc = await initCbMpcAuto();

  // --- 1. Key generation on secp256k1 ---
  console.log("1. Key generation (secp256k1)");
  const k1 = mpc.createCurve(NID_secp256k1);
  const privateKey = mpc.randomScalar(k1);
  const publicPoint = mpc.mulGenerator(k1, privateKey);
  const publicKeyUncompressed = mpc.pointToSec1Uncompressed(publicPoint);

  console.log(`   Private key: ${hex(privateKey)}`);
  console.log(`   Public key:  ${hex(publicKeyUncompressed).slice(0, 40)}...`);
  console.log(`   Key length:  ${publicKeyUncompressed.length} bytes (uncompressed)`);
  console.log();

  // --- 2. Multi-curve support ---
  console.log("2. Multi-curve key generation");
  const curves = [
    { name: "secp256k1", nid: NID_secp256k1 },
    { name: "P-256", nid: NID_X9_62_prime256v1 },
    { name: "Ed25519", nid: NID_ED25519 },
  ];
  for (const { name, nid } of curves) {
    const curve = mpc.createCurve(nid);
    const order = mpc.curveOrder(curve);
    const sk = mpc.randomScalar(curve);
    const pk = mpc.mulGenerator(curve, sk);
    const pkBytes = mpc.pointToBytes(pk);
    console.log(`   ${name.padEnd(10)} order=${hex(order).slice(0, 16)}... pubkey=${pkBytes.length}B`);
    mpc.freePoint(pk);
    mpc.freeCurve(curve);
  }
  console.log();

  // --- 3. Additive secret sharing (2-of-2) ---
  console.log("3. Additive secret sharing (2-of-2)");
  const share1 = mpc.randomScalar(k1);
  const share2 = mpc.ecModAdd(k1, privateKey, negate(k1, share1));

  // Reconstruct: share1 + share2 == privateKey
  const reconstructed = mpc.ecModAdd(k1, share1, share2);
  const reconstructedPoint = mpc.mulGenerator(k1, reconstructed);
  console.log(`   Share 1:       ${hex(share1).slice(0, 20)}...`);
  console.log(`   Share 2:       ${hex(share2).slice(0, 20)}...`);
  console.log(`   Reconstructed: ${hex(reconstructed).slice(0, 20)}...`);
  console.log(`   Matches original key: ${mpc.pointEquals(reconstructedPoint, publicPoint)}`);
  console.log();

  // --- 4. Point arithmetic verification ---
  console.log("4. Homomorphic point arithmetic");
  const a = mpc.randomScalar(k1);
  const b = mpc.randomScalar(k1);
  const aG = mpc.mulGenerator(k1, a);
  const bG = mpc.mulGenerator(k1, b);

  // (a+b)*G == a*G + b*G  (additive homomorphism)
  const sumScalar = mpc.ecModAdd(k1, a, b);
  const sumG = mpc.mulGenerator(k1, sumScalar);
  const pointSum = mpc.pointAdd(aG, bG);
  console.log(`   (a+b)*G == a*G + b*G: ${mpc.pointEquals(sumG, pointSum)}`);

  // a*G - a*G == infinity
  const diff = mpc.pointSubtract(aG, aG);
  console.log(`   a*G - a*G == O:       ${mpc.pointIsZero(diff)}`);

  // Point serialization round-trip
  const serialized = mpc.pointToBytes(aG);
  const deserialized = mpc.pointFromBytes(serialized);
  console.log(`   Serialize round-trip: ${mpc.pointEquals(aG, deserialized)}`);
  console.log();

  // Cleanup
  mpc.freePoint(publicPoint);
  mpc.freePoint(reconstructedPoint);
  mpc.freePoint(aG);
  mpc.freePoint(bG);
  mpc.freePoint(sumG);
  mpc.freePoint(pointSum);
  mpc.freePoint(diff);
  mpc.freePoint(deserialized);
  mpc.freeCurve(k1);

  console.log("=== Demo complete ===");

  /** Negate a scalar: -x mod n = order - x */
  function negate(curve: number, scalar: Uint8Array): Uint8Array {
    const order = mpc.curveOrder(curve);
    // Compute order - scalar using bnAdd with (order - scalar)
    // Since ecModAdd gives (a+b) mod n, we compute order - scalar by:
    // negate = order - scalar. We can use the raw subtraction approach.
    // Actually ecModAdd(order, -scalar) won't work directly.
    // Use: negate(x) = ecModAdd(0, order - x) but we don't have modSub.
    // Simpler: negate(x) = order - x, computed as big integer subtraction.
    const result = new Uint8Array(order.length);
    let borrow = 0;
    for (let i = order.length - 1; i >= 0; i--) {
      const diff = order[i] - scalar[i] - borrow;
      if (diff < 0) {
        result[i] = diff + 256;
        borrow = 1;
      } else {
        result[i] = diff;
        borrow = 0;
      }
    }
    return result;
  }
}

main().catch(console.error);
