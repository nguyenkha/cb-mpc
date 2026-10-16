// Smoke test for a prebuilt native library on the current OS/arch: load it
// through koffi (Node) and check a few results against the WASM build.
// Used by CI to prove the Linux .so loads on older distros (e.g. Debian 11/12).
//
// Usage: node scripts/native-smoke.mjs <package dir>   (needs `npm install koffi` there)

import { resolve, join } from "node:path";
import { existsSync } from "node:fs";

const pkg = resolve(process.argv[2] || ".");
const musl = process.platform === "linux" && existsSync(process.arch === "arm64" ? "/lib/ld-musl-aarch64.so.1" : "/lib/ld-musl-x86_64.so.1");
const platform = `${process.platform === "darwin" ? "darwin" : "linux"}-${process.arch === "arm64" ? "arm64" : "x64"}${musl ? "-musl" : ""}`;
const lib = join(pkg, "prebuilds", platform, `libcbmpc.${process.platform === "darwin" ? "dylib" : "so"}`);
if (!existsSync(lib)) {
  console.error(`FAIL: no prebuild for ${platform} at ${lib}`);
  process.exit(1);
}

const M = await import(join(pkg, "dist", "index.js"));
const native = await M.initCbMpcKoffi(lib);
const wasm = await M.initCbMpc();
const hex = (b) => Buffer.from(b).toString("hex");

let failed = 0;
for (const [name, code] of [["secp256k1", M.NID_secp256k1], ["P-256", M.NID_X9_62_prime256v1], ["Ed25519", M.NID_ED25519]]) {
  const cn = native.createCurve(code);
  const cw = wasm.createCurve(code);
  const k = native.randomScalar(cn);
  const a = hex(native.pointToBytes(native.mulGenerator(cn, k)));
  const b = hex(wasm.pointToBytes(wasm.mulGenerator(cw, k)));
  const ok = a === b;
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: native k*G == WASM k*G`);
}
const hash = new Uint8Array(32).fill(1);
const badSig = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
const c = native.createCurve(M.NID_secp256k1);
const pub = native.pointToSec1Uncompressed
  ? native.pointToSec1Uncompressed(native.mulGenerator(c, native.randomScalar(c)))
  : null;
if (pub && native.verifyDer(M.NID_secp256k1, pub, hash, badSig)) {
  failed++;
  console.log("FAIL verifyDer accepted a bogus signature");
} else {
  console.log("PASS verifyDer rejects a bogus signature");
}

console.log(`${platform} (${process.version}): ${failed ? "FAILED" : "all passed"} — ${lib}`);
process.exit(failed ? 1 : 0);
