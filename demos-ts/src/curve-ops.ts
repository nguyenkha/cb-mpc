/**
 * Elliptic Curve Operations Demo
 *
 * Demonstrates low-level curve and point operations:
 *   - Creating curves and accessing their parameters
 *   - Random scalar generation
 *   - Generator point multiplication
 *   - Point addition, subtraction, and equality
 *   - Scalar arithmetic (modular addition)
 *   - Point serialization round-trips
 */

import { initCbMpc, NID_secp256k1, NID_X9_62_prime256v1 } from "cb-mpc";

async function main() {
  console.log("=== Elliptic Curve Operations Demo ===\n");

  const mpc = await initCbMpc();

  // --- Curve creation ---
  console.log("1. Curve parameters");
  const secp256k1 = mpc.createCurve(NID_secp256k1);
  const p256 = mpc.createCurve(NID_X9_62_prime256v1);

  const order = mpc.curveOrder(secp256k1);
  console.log(`   secp256k1 order (${order.length} bytes): ${hexEncode(order)}`);
  console.log(`   secp256k1 NID: ${mpc.curveCode(secp256k1)}`);

  const orderP256 = mpc.curveOrder(p256);
  console.log(`   P-256 order (${orderP256.length} bytes): ${hexEncode(orderP256)}`);
  console.log();

  // --- Random scalars ---
  console.log("2. Random scalar generation");
  const scalar1 = mpc.randomScalar(secp256k1);
  const scalar2 = mpc.randomScalar(secp256k1);
  console.log(`   Random scalar 1: ${hexEncode(scalar1)}`);
  console.log(`   Random scalar 2: ${hexEncode(scalar2)}`);
  console.log(`   Scalars are different: ${hexEncode(scalar1) !== hexEncode(scalar2)}`);
  console.log();

  // --- Generator multiplication ---
  console.log("3. Generator point multiplication");
  // Compute P = scalar1 * G
  const P = mpc.mulGenerator(secp256k1, scalar1);
  const coords = mpc.pointCoordinates(P);
  console.log(`   P = scalar1 * G`);
  console.log(`   P.x: ${hexEncode(coords.x)}`);
  console.log(`   P.y: ${hexEncode(coords.y)}`);
  console.log(`   P is infinity: ${mpc.pointIsZero(P)}`);
  console.log();

  // --- Point addition ---
  console.log("4. Point addition and subtraction");
  // Compute Q = scalar2 * G
  const Q = mpc.mulGenerator(secp256k1, scalar2);

  // R = P + Q
  const R = mpc.pointAdd(P, Q);
  const rCoords = mpc.pointCoordinates(R);
  console.log(`   R = P + Q`);
  console.log(`   R.x: ${hexEncode(rCoords.x)}`);

  // Verify: R should equal (scalar1 + scalar2) * G
  const sumScalar = mpc.ecModAdd(secp256k1, scalar1, scalar2);
  const Rexpected = mpc.mulGenerator(secp256k1, sumScalar);
  console.log(`   R == (s1 + s2) * G: ${mpc.pointEquals(R, Rexpected)}`);

  // S = R - Q should equal P
  const S = mpc.pointSubtract(R, Q);
  console.log(`   R - Q == P: ${mpc.pointEquals(S, P)}`);
  console.log();

  // --- Point serialization ---
  console.log("5. Point serialization round-trip");
  const serialized = mpc.pointToBytes(P);
  console.log(`   Serialized point (${serialized.length} bytes)`);

  const deserialized = mpc.pointFromBytes(serialized);
  console.log(`   Round-trip matches: ${mpc.pointEquals(P, deserialized)}`);
  console.log();

  // --- Scalar arithmetic ---
  console.log("6. Scalar arithmetic");
  const a = mpc.randomScalar(secp256k1);
  const b = mpc.randomScalar(secp256k1);
  const sum = mpc.ecModAdd(secp256k1, a, b);
  console.log(`   a:     ${hexEncode(a)}`);
  console.log(`   b:     ${hexEncode(b)}`);
  console.log(`   a + b mod n: ${hexEncode(sum)}`);

  // Verify: (a * G) + (b * G) == (a + b) * G
  const aG = mpc.mulGenerator(secp256k1, a);
  const bG = mpc.mulGenerator(secp256k1, b);
  const abG = mpc.pointAdd(aG, bG);
  const sumG = mpc.mulGenerator(secp256k1, sum);
  console.log(`   aG + bG == (a+b)G: ${mpc.pointEquals(abG, sumG)}`);
  console.log();

  // --- Cleanup ---
  mpc.freePoint(P);
  mpc.freePoint(Q);
  mpc.freePoint(R);
  mpc.freePoint(Rexpected);
  mpc.freePoint(S);
  mpc.freePoint(deserialized);
  mpc.freePoint(aG);
  mpc.freePoint(bG);
  mpc.freePoint(abG);
  mpc.freePoint(sumG);
  mpc.freeCurve(secp256k1);
  mpc.freeCurve(p256);

  console.log("=== Demo complete ===");
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

main().catch(console.error);
