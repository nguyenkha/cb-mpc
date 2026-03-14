/**
 * Agreed Random Demo
 *
 * Two parties collaboratively generate a random value that neither
 * party can bias. Both parties end up with the same random bytes.
 *
 * Each party uses its own CbMpc instance because Emscripten ASYNCIFY
 * only supports one suspended async call stack per WASM module.
 */

import { initCbMpc } from "../dist/index";
import { createMockNetwork } from "./mock-transport";

const PARTY_NAMES: [string, string] = ["alice", "bob"];

async function main() {
  console.log("=== Agreed Random Demo ===\n");

  // Each party needs its own WASM module instance for concurrent execution.
  const [mpc0, mpc1] = await Promise.all([initCbMpc(), initCbMpc()]);
  const transports = createMockNetwork(2);

  const bitLen = 256;
  console.log(`Generating ${bitLen}-bit agreed random value...\n`);

  const [random0, random1] = await Promise.all([
    mpc0.agreeRandom(transports[0], 0, PARTY_NAMES, bitLen),
    mpc1.agreeRandom(transports[1], 1, PARTY_NAMES, bitLen),
  ]);

  console.log(`Party 0: ${hexEncode(random0)}`);
  console.log(`Party 1: ${hexEncode(random1)}`);
  console.log(`\nValues match: ${hexEncode(random0) === hexEncode(random1)}`);

  console.log("\n=== Demo complete ===");
}

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

main().catch(console.error);
