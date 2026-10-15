/**
 * cb-mpc TypeScript wrapper.
 *
 * Provides a type-safe, ergonomic API over the native C library.
 * Supports three backends:
 *   - WASM (Emscripten) for browsers
 *   - bun:ffi for Bun runtime
 *   - koffi for Node.js runtime
 *
 * All opaque pointers are wrapped in handle types. The CbMpc class is
 * backend-agnostic — it works with any CbMpcModule implementation.
 */

import type { CbMpcModule } from "./module.js";

// Debug logging — optional dependency, falls back to no-op in browsers
let debug: (...args: any[]) => void = () => {};
try {
  // Use indirect import to avoid browser module resolution errors
  const _require = typeof require === "function" ? require : undefined;
  if (_require) {
    const debug_module = _require("debug");
    const createDebug = typeof debug_module === "function" ? debug_module : debug_module.default;
    debug = createDebug("cb-mpc");
  }
} catch {
  // debug module not available, use no-op
}
import type {
  CurveHandle,
  PointHandle,
  Ecdsa2pKeyHandle,
  EcKey2pHandle,
  EcKeyMpHandle,
  DataTransport,
  Ecdsa2pKeyInfo,
  EcKey2pInfo,
  EcKeyMpInfo,
  EcPoint,
  CbMpcWasmModule,
  HdEcdsa2pKeysetHandle,
  HdEddsa2pKeysetHandle,
  HdKeysetInfo,
  HdAccountNode,
} from "./types.js";

export type { CbMpcModule } from "./module.js";
export * from "./types.js";
export * from "./access-structure.js";
import { type AccessStructure, encodeAccessStructure } from "./access-structure.js";

// ---------------------------------------------------------------------------
// Module initialization
// ---------------------------------------------------------------------------

/**
 * Initialize cb-mpc with the WASM backend (browser & Node.js).
 *
 * Each call returns a new CbMpc instance backed by a separate WASM module.
 * For concurrent MPC parties, create one instance per party.
 */
export async function initCbMpc(
  wasmModuleFactory?: (opts?: object) => Promise<CbMpcWasmModule>,
): Promise<CbMpc> {
  const { createWasmBackend } = await import("./backends/wasm.js");
  const backend = await createWasmBackend(wasmModuleFactory);
  return new CbMpc(backend);
}

/**
 * Initialize cb-mpc with the bun:ffi native backend (Bun only).
 *
 * @param libPath - Optional path to the shared library. Auto-detected if omitted.
 */
export async function initCbMpcBunFfi(libPath?: string): Promise<CbMpc> {
  const { createBunFfiBackend } = await import("./backends/bun-ffi.js");
  const backend = await createBunFfiBackend(libPath);
  return new CbMpc(backend);
}

/**
 * Initialize cb-mpc with the koffi native backend (Node.js & Bun).
 *
 * Requires: npm install koffi
 *
 * @param libPath - Optional path to the shared library. Auto-detected if omitted.
 */
export async function initCbMpcKoffi(libPath?: string): Promise<CbMpc> {
  const { createKoffiBackend } = await import("./backends/koffi-ffi.js");
  const backend = await createKoffiBackend(libPath);
  return new CbMpc(backend);
}

/**
 * Auto-detect the best available backend and initialize.
 *
 * Priority: bun:ffi (if Bun + prebuilt exists) > koffi (if installed + prebuilt exists) > WASM (fallback)
 */
export async function initCbMpcAuto(): Promise<CbMpc> {
  // Check if running in Bun
  if (typeof globalThis !== "undefined" && (globalThis as any).Bun) {
    try {
      const mpc = await initCbMpcBunFfi();
      debug("loaded bun:ffi backend");
      return mpc;
    } catch (e) {
      debug("bun:ffi backend failed: %s", (e as Error).message);
    }
  }

  // Try koffi (Node.js or Bun with koffi installed)
  if (typeof process !== "undefined" && process.versions) {
    try {
      // Throws when koffi is not installed or no prebuilt library exists.
      const mpc = await initCbMpcKoffi();
      debug("loaded koffi backend");
      return mpc;
    } catch {
      // koffi not installed, fall through
    }
  }

  // Fallback to WASM
  const mpc = await initCbMpc();
  debug("loaded wasm backend");
  return mpc;
}

// ---------------------------------------------------------------------------
// Error class
// ---------------------------------------------------------------------------

/** Split a non-negative safe integer into [lo, hi] uint32 halves passed as i32. */
function splitU64(v: number): [number, number] {
  if (!Number.isSafeInteger(v) || v < 0) throw new RangeError("aux must be a non-negative safe integer");
  return [v % 0x100000000 | 0, Math.floor(v / 0x100000000) | 0];
}

export class CbMpcError extends Error {
  constructor(
    public readonly code: number,
    public readonly operation: string,
  ) {
    super(`cb-mpc error ${code} during ${operation}`);
    this.name = "CbMpcError";
  }
}

function checkError(code: number, operation: string): void {
  if (code !== 0) {
    throw new CbMpcError(code, operation);
  }
}

// ---------------------------------------------------------------------------
// Transport ID management
// ---------------------------------------------------------------------------

let nextTransportId = 1;

// ---------------------------------------------------------------------------
// Main API class
// ---------------------------------------------------------------------------

export class CbMpc {
  /** @internal */
  constructor(private readonly mod: CbMpcModule) {}

  // =========================================================================
  // Curve operations
  // =========================================================================

  createCurve(curveCode: number): CurveHandle {
    const outPtr = this.mod.allocRef();
    const status = this.mod.call("wasm_new_ecurve", curveCode, outPtr) as number;
    const handle = this.mod.readRef(outPtr);
    this.mod.free(outPtr);
    checkError(status, "wasm_new_ecurve");
    return handle as unknown as CurveHandle;
  }

  freeCurve(handle: CurveHandle): void {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, handle as unknown as number);
    this.mod.call("wasm_free_ecurve", refPtr);
    this.mod.free(refPtr);
  }

  curveGenerator(curve: CurveHandle): PointHandle {
    const curveRef = this.mod.allocRef();
    this.mod.setPointer(curveRef, curve as unknown as number);
    const outPtr = this.mod.allocRef();
    const status = this.mod.call("wasm_ecurve_generator", curveRef, outPtr) as number;
    const handle = this.mod.readRef(outPtr);
    this.mod.free(curveRef);
    this.mod.free(outPtr);
    checkError(status, "wasm_ecurve_generator");
    return handle as unknown as PointHandle;
  }

  curveOrder(curve: CurveHandle): Uint8Array {
    const curveRef = this.mod.allocRef();
    this.mod.setPointer(curveRef, curve as unknown as number);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    const status = this.mod.call("wasm_ecurve_order", curveRef, cmemOut) as number;
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(curveRef);
    checkError(status, "wasm_ecurve_order");
    return result;
  }

  curveCode(curve: CurveHandle): number {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, curve as unknown as number);
    const code = this.mod.call("ecurve_get_curve_code", refPtr);
    this.mod.free(refPtr);
    return code;
  }

  randomScalar(curve: CurveHandle): Uint8Array {
    const curveRef = this.mod.allocRef();
    this.mod.setPointer(curveRef, curve as unknown as number);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    const status = this.mod.call("wasm_ecurve_random_scalar", curveRef, cmemOut) as number;
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(curveRef);
    checkError(status, "wasm_ecurve_random_scalar");
    return result;
  }

  // =========================================================================
  // Point operations
  // =========================================================================

  pointFromBytes(data: Uint8Array): PointHandle {
    const dataPtr = this.mod.writeBytes(data);
    const outPtr = this.mod.allocRef();
    const status = this.mod.call("wasm_ecc_point_from_bytes", dataPtr, data.length, outPtr) as number;
    const handle = this.mod.readRef(outPtr);
    this.mod.free(outPtr);
    this.mod.free(dataPtr);
    checkError(status, "wasm_ecc_point_from_bytes");
    return handle as unknown as PointHandle;
  }

  pointToBytes(point: PointHandle): Uint8Array {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, point as unknown as number);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    const status = this.mod.call("wasm_ecc_point_to_bytes", refPtr, cmemOut) as number;
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(refPtr);
    checkError(status, "wasm_ecc_point_to_bytes");
    return result;
  }

  pointGetX(point: PointHandle): Uint8Array {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, point as unknown as number);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    const status = this.mod.call("wasm_ecc_point_get_x", refPtr, cmemOut) as number;
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(refPtr);
    checkError(status, "wasm_ecc_point_get_x");
    return result;
  }

  pointGetY(point: PointHandle): Uint8Array {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, point as unknown as number);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    const status = this.mod.call("wasm_ecc_point_get_y", refPtr, cmemOut) as number;
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(refPtr);
    checkError(status, "wasm_ecc_point_get_y");
    return result;
  }

  pointCoordinates(point: PointHandle): EcPoint {
    return { x: this.pointGetX(point), y: this.pointGetY(point) };
  }

  pointMultiply(point: PointHandle, scalar: Uint8Array): PointHandle {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, point as unknown as number);
    const sPtr = this.mod.writeBytes(scalar);
    const outPtr = this.mod.allocRef();
    const status = this.mod.call("wasm_ecc_point_multiply", refPtr, sPtr, scalar.length, outPtr) as number;
    const handle = this.mod.readRef(outPtr);
    this.mod.free(refPtr);
    this.mod.free(sPtr);
    this.mod.free(outPtr);
    checkError(status, "wasm_ecc_point_multiply");
    return handle as unknown as PointHandle;
  }

  pointAdd(p1: PointHandle, p2: PointHandle): PointHandle {
    const ref1 = this.mod.allocRef();
    const ref2 = this.mod.allocRef();
    this.mod.setPointer(ref1, p1 as unknown as number);
    this.mod.setPointer(ref2, p2 as unknown as number);
    const outPtr = this.mod.allocRef();
    const status = this.mod.call("wasm_ecc_point_add", ref1, ref2, outPtr) as number;
    const handle = this.mod.readRef(outPtr);
    this.mod.free(ref1);
    this.mod.free(ref2);
    this.mod.free(outPtr);
    checkError(status, "wasm_ecc_point_add");
    return handle as unknown as PointHandle;
  }

  pointSubtract(p1: PointHandle, p2: PointHandle): PointHandle {
    const ref1 = this.mod.allocRef();
    const ref2 = this.mod.allocRef();
    this.mod.setPointer(ref1, p1 as unknown as number);
    this.mod.setPointer(ref2, p2 as unknown as number);
    const outPtr = this.mod.allocRef();
    const status = this.mod.call("wasm_ecc_point_subtract", ref1, ref2, outPtr) as number;
    const handle = this.mod.readRef(outPtr);
    this.mod.free(ref1);
    this.mod.free(ref2);
    this.mod.free(outPtr);
    checkError(status, "wasm_ecc_point_subtract");
    return handle as unknown as PointHandle;
  }

  pointIsZero(point: PointHandle): boolean {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, point as unknown as number);
    const result = this.mod.call("ecc_point_is_zero", refPtr);
    this.mod.free(refPtr);
    return result === 1;
  }

  pointEquals(p1: PointHandle, p2: PointHandle): boolean {
    const ref1 = this.mod.allocRef();
    const ref2 = this.mod.allocRef();
    this.mod.setPointer(ref1, p1 as unknown as number);
    this.mod.setPointer(ref2, p2 as unknown as number);
    const result = this.mod.call("ecc_point_equals", ref1, ref2);
    this.mod.free(ref1);
    this.mod.free(ref2);
    return result === 1;
  }

  freePoint(point: PointHandle): void {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, point as unknown as number);
    this.mod.call("wasm_free_ecc_point", refPtr);
    this.mod.free(refPtr);
  }

  mulGenerator(curve: CurveHandle, scalar: Uint8Array): PointHandle {
    const curveRef = this.mod.allocRef();
    this.mod.setPointer(curveRef, curve as unknown as number);
    const sPtr = this.mod.writeBytes(scalar);
    const outPtr = this.mod.allocRef();
    const status = this.mod.call("wasm_ecurve_mul_generator", curveRef, sPtr, scalar.length, outPtr) as number;
    const handle = this.mod.readRef(outPtr);
    this.mod.free(curveRef);
    this.mod.free(sPtr);
    this.mod.free(outPtr);
    checkError(status, "wasm_ecurve_mul_generator");
    return handle as unknown as PointHandle;
  }

  /** Get SEC1 uncompressed public key (04 || x || y) from a point handle. */
  pointToSec1Uncompressed(point: PointHandle): Uint8Array {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, point as unknown as number);
    const result = this.mod.pointToSec1(refPtr);
    this.mod.free(refPtr);
    return result;
  }

  verifyDer(
    curveCode: number,
    publicKeyOct: Uint8Array,
    hash: Uint8Array,
    derSig: Uint8Array,
  ): boolean {
    const pubPtr = this.mod.writeBytes(publicKeyOct);
    const hashPtr = this.mod.writeBytes(hash);
    const sigPtr = this.mod.writeBytes(derSig);
    const result = this.mod.call(
      "wasm_ecc_verify_der",
      curveCode,
      pubPtr, publicKeyOct.length,
      hashPtr, hash.length,
      sigPtr, derSig.length,
    );
    this.mod.free(pubPtr);
    this.mod.free(hashPtr);
    this.mod.free(sigPtr);
    return result === 0;
  }

  // =========================================================================
  // Scalar operations
  // =========================================================================

  bnAdd(a: Uint8Array, b: Uint8Array): Uint8Array {
    const aPtr = this.mod.writeBytes(a);
    const bPtr = this.mod.writeBytes(b);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    const status = this.mod.call("wasm_bn_add", aPtr, a.length, bPtr, b.length, cmemOut) as number;
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(aPtr);
    this.mod.free(bPtr);
    checkError(status, "wasm_bn_add");
    return result;
  }

  ecModAdd(curve: CurveHandle, a: Uint8Array, b: Uint8Array): Uint8Array {
    const curveRef = this.mod.allocRef();
    this.mod.setPointer(curveRef, curve as unknown as number);
    const aPtr = this.mod.writeBytes(a);
    const bPtr = this.mod.writeBytes(b);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    const status = this.mod.call("wasm_ec_mod_add", curveRef, aPtr, a.length, bPtr, b.length, cmemOut) as number;
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(curveRef);
    this.mod.free(aPtr);
    this.mod.free(bPtr);
    checkError(status, "wasm_ec_mod_add");
    return result;
  }

  // =========================================================================
  // Transport management (internal)
  // =========================================================================

  private registerTransport(transport: DataTransport): number {
    const id = nextTransportId++;
    this.mod.registerTransport(id, transport);
    return id;
  }

  private unregisterTransport(id: number): void {
    this.mod.unregisterTransport(id);
  }

  // =========================================================================
  // Internal helpers for key info extraction
  // =========================================================================

  private extractPublicKey(getQFn: string, keyRef: number): Uint8Array {
    const qOut = this.mod.allocRef();
    const status = this.mod.call(getQFn, keyRef, qOut) as number;
    const qHandle = this.mod.readRef(qOut);
    this.mod.free(qOut);
    checkError(status, getQFn);
    const qRef = this.mod.allocRef();
    this.mod.setPointer(qRef, qHandle);
    const publicKey = this.mod.pointToSec1(qRef);
    this.mod.free(qRef);
    const freeRef = this.mod.allocRef();
    this.mod.setPointer(freeRef, qHandle);
    this.mod.call("wasm_free_ecc_point", freeRef);
    this.mod.free(freeRef);
    return publicKey;
  }

  private extractXShare(getXShareFn: string, keyRef: number): Uint8Array {
    const xCmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    const status = this.mod.call(getXShareFn, keyRef, xCmemOut) as number;
    const xShare = this.mod.readCmem(xCmemOut);
    this.mod.freeCmem(xCmemOut);
    checkError(status, getXShareFn);
    return xShare;
  }

  // =========================================================================
  // ECDSA Two-Party Protocol
  // =========================================================================

  async ecdsa2pDkg(
    transport: DataTransport,
    partyIndex: number,
    partyNames: [string, string],
    curveCode: number,
  ): Promise<Ecdsa2pKeyHandle> {
    const transportId = this.registerTransport(transport);
    const name0 = this.mod.allocString(partyNames[0]);
    const name1 = this.mod.allocString(partyNames[1]);

    let jobPtr = 0;
    try {
      jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, "ecdsa2pDkg: failed to create job");

      const keyRef = this.mod.allocRef();
      const err = await this.mod.callAsync("mpc_ecdsa2p_dkg", jobPtr, curveCode, keyRef);
      const keyHandle = this.mod.readRef(keyRef) as unknown as Ecdsa2pKeyHandle;
      this.mod.free(keyRef);

      checkError(err, "ecdsa2pDkg");
      return keyHandle;
    } finally {
      if (jobPtr) this.mod.call("free_job_2p", jobPtr);
      this.mod.free(name0);
      this.mod.free(name1);
      this.unregisterTransport(transportId);
    }
  }

  async ecdsa2pSign(
    transport: DataTransport,
    partyIndex: number,
    partyNames: [string, string],
    key: Ecdsa2pKeyHandle,
    sessionId: Uint8Array,
    messages: Uint8Array[],
  ): Promise<Uint8Array[]> {
    const transportId = this.registerTransport(transport);
    const name0 = this.mod.allocString(partyNames[0]);
    const name1 = this.mod.allocString(partyNames[1]);

    let jobPtr = 0;
    try {
      jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, "ecdsa2pSign: failed to create job");

      const sidCmem = this.mod.writeCmem(sessionId);
      const keyRef = this.mod.allocRef();
      this.mod.setPointer(keyRef, key as unknown as number);
      const msgsCmems = this.mod.writeCmems(messages);
      // cmems_t size: int + 2 pointers
      const sigsCmemsSize = this.mod.POINTER_SIZE * 3;
      const sigsCmems = this.mod.malloc(sigsCmemsSize);

      const err = await this.mod.callAsync(
        "wasm_mpc_ecdsa2p_sign", jobPtr, sidCmem, keyRef, msgsCmems, sigsCmems,
      );

      const sigs = err === 0 ? this.mod.readCmems(sigsCmems) : [];

      this.mod.free(keyRef);
      this.mod.freeCmem(sidCmem);
      this.mod.freeCmems(msgsCmems);
      this.mod.freeCmems(sigsCmems);

      checkError(err, "ecdsa2pSign");
      return sigs;
    } finally {
      if (jobPtr) this.mod.call("free_job_2p", jobPtr);
      this.mod.free(name0);
      this.mod.free(name1);
      this.unregisterTransport(transportId);
    }
  }

  async ecdsa2pRefresh(
    transport: DataTransport,
    partyIndex: number,
    partyNames: [string, string],
    key: Ecdsa2pKeyHandle,
  ): Promise<Ecdsa2pKeyHandle> {
    const transportId = this.registerTransport(transport);
    const name0 = this.mod.allocString(partyNames[0]);
    const name1 = this.mod.allocString(partyNames[1]);

    let jobPtr = 0;
    try {
      jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, "ecdsa2pRefresh: failed to create job");

      const keyRef = this.mod.allocRef();
      this.mod.setPointer(keyRef, key as unknown as number);
      const newKeyRef = this.mod.allocRef();

      const err = await this.mod.callAsync("mpc_ecdsa2p_refresh", jobPtr, keyRef, newKeyRef);
      const newKey = this.mod.readRef(newKeyRef) as unknown as Ecdsa2pKeyHandle;

      this.mod.free(keyRef);
      this.mod.free(newKeyRef);

      checkError(err, "ecdsa2pRefresh");
      return newKey;
    } finally {
      if (jobPtr) this.mod.call("free_job_2p", jobPtr);
      this.mod.free(name0);
      this.mod.free(name1);
      this.unregisterTransport(transportId);
    }
  }

  ecdsa2pKeyInfo(key: Ecdsa2pKeyHandle): Ecdsa2pKeyInfo {
    const keyRef = this.mod.allocRef();
    this.mod.setPointer(keyRef, key as unknown as number);

    const roleIndex = this.mod.call("mpc_ecdsa2p_key_get_role_index", keyRef);
    const curveCode = this.mod.call("mpc_ecdsa2p_key_get_curve_code", keyRef);
    const publicKey = this.extractPublicKey("wasm_mpc_ecdsa2p_key_get_Q", keyRef);
    const xShare = this.extractXShare("wasm_mpc_ecdsa2p_key_get_x_share", keyRef);

    this.mod.free(keyRef);
    return { roleIndex, curveCode, publicKey, xShare };
  }

  reconstructKey(curveCode: number, xShares: Uint8Array[]): Uint8Array {
    if (xShares.length < 2) throw new Error("Need at least 2 shares");
    const curve = this.createCurve(curveCode);
    try {
      let result = xShares[0];
      for (let i = 1; i < xShares.length; i++) {
        result = this.ecModAdd(curve, result, xShares[i]);
      }
      return result;
    } finally {
      this.freeCurve(curve);
    }
  }

  freeEcdsa2pKey(key: Ecdsa2pKeyHandle): void {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, key as unknown as number);
    this.mod.call("wasm_free_mpc_ecdsa2p_key", refPtr);
    this.mod.free(refPtr);
  }

  serializeEcdsa2p(key: Ecdsa2pKeyHandle): Uint8Array[] {
    const keyRef = this.mod.allocRef();
    this.mod.setPointer(keyRef, key as unknown as number);
    const cmemsSize = this.mod.POINTER_SIZE * 3;
    const serCmems = this.mod.malloc(cmemsSize);

    const err = this.mod.call("serialize_mpc_ecdsa2p", keyRef, serCmems);
    const result = err === 0 ? this.mod.readCmems(serCmems) : [];
    this.mod.freeCmems(serCmems);
    this.mod.free(keyRef);
    checkError(err, "serializeEcdsa2p");
    return result;
  }

  deserializeEcdsa2p(data: Uint8Array[]): Ecdsa2pKeyHandle {
    const serCmems = this.mod.writeCmems(data);
    const keyRef = this.mod.allocRef();

    const err = this.mod.call("wasm_deserialize_mpc_ecdsa2p", serCmems, keyRef);
    const keyHandle = this.mod.readRef(keyRef) as unknown as Ecdsa2pKeyHandle;
    this.mod.free(keyRef);
    this.mod.freeCmems(serCmems);
    checkError(err, "deserializeEcdsa2p");
    return keyHandle;
  }

  // =========================================================================
  // Schnorr Two-Party Protocol (EdDSA)
  // =========================================================================

  async ecKey2pDkg(
    transport: DataTransport,
    partyIndex: number,
    partyNames: [string, string],
    curveCode: number,
  ): Promise<EcKey2pHandle> {
    const transportId = this.registerTransport(transport);
    const name0 = this.mod.allocString(partyNames[0]);
    const name1 = this.mod.allocString(partyNames[1]);

    let jobPtr = 0;
    try {
      jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, "ecKey2pDkg: failed to create job");

      const keyRef = this.mod.allocRef();
      const err = await this.mod.callAsync("mpc_eckey_2p_dkg", jobPtr, curveCode, keyRef);
      const keyHandle = this.mod.readRef(keyRef) as unknown as EcKey2pHandle;
      this.mod.free(keyRef);

      checkError(err, "ecKey2pDkg");
      return keyHandle;
    } finally {
      if (jobPtr) this.mod.call("free_job_2p", jobPtr);
      this.mod.free(name0);
      this.mod.free(name1);
      this.unregisterTransport(transportId);
    }
  }

  async schnorr2pEddsaSign(
    transport: DataTransport,
    partyIndex: number,
    partyNames: [string, string],
    key: EcKey2pHandle,
    message: Uint8Array,
  ): Promise<Uint8Array> {
    const transportId = this.registerTransport(transport);
    const name0 = this.mod.allocString(partyNames[0]);
    const name1 = this.mod.allocString(partyNames[1]);

    let jobPtr = 0;
    try {
      jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, "schnorr2pEddsaSign: failed to create job");

      const keyRef = this.mod.allocRef();
      this.mod.setPointer(keyRef, key as unknown as number);
      const msgPtr = this.mod.writeBytes(message);
      const sigCmem = this.mod.malloc(this.mod.CMEM_SIZE);

      const err = await this.mod.callAsync(
        "wasm_mpc_schnorr2p_eddsa_sign", jobPtr, keyRef, msgPtr, message.length, sigCmem,
      );

      const sig = err === 0 ? this.mod.readCmem(sigCmem) : new Uint8Array(0);

      this.mod.free(keyRef);
      this.mod.free(msgPtr);
      this.mod.freeCmem(sigCmem);

      checkError(err, "schnorr2pEddsaSign");
      return sig;
    } finally {
      if (jobPtr) this.mod.call("free_job_2p", jobPtr);
      this.mod.free(name0);
      this.mod.free(name1);
      this.unregisterTransport(transportId);
    }
  }

  ecKey2pInfo(key: EcKey2pHandle): EcKey2pInfo {
    const keyRef = this.mod.allocRef();
    this.mod.setPointer(keyRef, key as unknown as number);

    const roleIndex = this.mod.call("mpc_eckey_2p_get_role_index", keyRef);
    const curveCode = this.mod.call("mpc_eckey_2p_get_curve_code", keyRef);
    const publicKey = this.extractPublicKey("wasm_mpc_eckey_2p_get_Q", keyRef);
    const xShare = this.extractXShare("wasm_mpc_eckey_2p_get_x_share", keyRef);

    this.mod.free(keyRef);
    return { roleIndex, curveCode, publicKey, xShare };
  }

  freeEcKey2p(key: EcKey2pHandle): void {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, key as unknown as number);
    this.mod.call("wasm_free_mpc_eckey_2p", refPtr);
    this.mod.free(refPtr);
  }

  serializeEcKey2p(key: EcKey2pHandle): Uint8Array[] {
    const keyRef = this.mod.allocRef();
    this.mod.setPointer(keyRef, key as unknown as number);
    const cmemsSize = this.mod.POINTER_SIZE * 3;
    const serCmems = this.mod.malloc(cmemsSize);

    const err = this.mod.call("serialize_mpc_eckey_2p", keyRef, serCmems);
    const result = err === 0 ? this.mod.readCmems(serCmems) : [];
    this.mod.freeCmems(serCmems);
    this.mod.free(keyRef);
    checkError(err, "serializeEcKey2p");
    return result;
  }

  deserializeEcKey2p(data: Uint8Array[]): EcKey2pHandle {
    const serCmems = this.mod.writeCmems(data);
    const keyRef = this.mod.allocRef();

    const err = this.mod.call("wasm_deserialize_mpc_eckey_2p", serCmems, keyRef);
    const keyHandle = this.mod.readRef(keyRef) as unknown as EcKey2pHandle;
    this.mod.free(keyRef);
    this.mod.freeCmems(serCmems);
    checkError(err, "deserializeEcKey2p");
    return keyHandle;
  }

  // =========================================================================
  // EC Key Multi-Party Protocol
  // =========================================================================

  async ecKeyMpDkg(
    transport: DataTransport,
    partyCount: number,
    partyIndex: number,
    partyNames: string[],
    curve: CurveHandle,
  ): Promise<EcKeyMpHandle> {
    const transportId = this.registerTransport(transport);
    const { arrayPtr: namesArray, namePtrs } = this.mod.allocPartyNames(partyNames);

    let jobPtr = 0;
    try {
      jobPtr = this.mod.call(
        "wasm_new_job_mp", transportId, partyCount, partyIndex, namesArray, partyNames.length,
      );
      if (!jobPtr) throw new CbMpcError(-1, "ecKeyMpDkg: failed to create job");

      const curveRef = this.mod.allocRef();
      this.mod.setPointer(curveRef, curve as unknown as number);
      const keyRef = this.mod.allocRef();

      const err = await this.mod.callAsync("mpc_eckey_mp_dkg", jobPtr, curveRef, keyRef);
      const keyHandle = this.mod.readRef(keyRef) as unknown as EcKeyMpHandle;

      this.mod.free(curveRef);
      this.mod.free(keyRef);

      checkError(err, "ecKeyMpDkg");
      return keyHandle;
    } finally {
      if (jobPtr) this.mod.call("free_job_mp", jobPtr);
      for (const p of namePtrs) this.mod.free(p);
      this.mod.free(namesArray);
      this.unregisterTransport(transportId);
    }
  }

  async ecKeyMpRefresh(
    transport: DataTransport,
    partyCount: number,
    partyIndex: number,
    partyNames: string[],
    key: EcKeyMpHandle,
    sessionId: Uint8Array,
  ): Promise<EcKeyMpHandle> {
    const transportId = this.registerTransport(transport);
    const { arrayPtr: namesArray, namePtrs } = this.mod.allocPartyNames(partyNames);

    let jobPtr = 0;
    try {
      jobPtr = this.mod.call(
        "wasm_new_job_mp", transportId, partyCount, partyIndex, namesArray, partyNames.length,
      );
      if (!jobPtr) throw new CbMpcError(-1, "ecKeyMpRefresh: failed to create job");

      const keyRef = this.mod.allocRef();
      this.mod.setPointer(keyRef, key as unknown as number);
      const sidCmem = this.mod.writeCmem(sessionId);
      const newKeyRef = this.mod.allocRef();

      const err = await this.mod.callAsync("wasm_mpc_eckey_mp_refresh", jobPtr, sidCmem, keyRef, newKeyRef);
      const newKey = this.mod.readRef(newKeyRef) as unknown as EcKeyMpHandle;

      this.mod.free(keyRef);
      this.mod.free(newKeyRef);
      this.mod.freeCmem(sidCmem);

      checkError(err, "ecKeyMpRefresh");
      return newKey;
    } finally {
      if (jobPtr) this.mod.call("free_job_mp", jobPtr);
      for (const p of namePtrs) this.mod.free(p);
      this.mod.free(namesArray);
      this.unregisterTransport(transportId);
    }
  }

  ecKeyMpInfo(key: EcKeyMpHandle): EcKeyMpInfo {
    const keyRef = this.mod.allocRef();
    this.mod.setPointer(keyRef, key as unknown as number);

    const nameCmem = this.mod.malloc(this.mod.CMEM_SIZE);
    this.mod.call("mpc_eckey_mp_get_party_name", keyRef, nameCmem);
    const nameData = this.mod.readCmem(nameCmem);
    const partyName = new TextDecoder().decode(nameData);
    this.mod.freeCmem(nameCmem);

    const publicKey = this.extractPublicKey("wasm_mpc_eckey_mp_get_Q", keyRef);

    const xCmem = this.mod.malloc(this.mod.CMEM_SIZE);
    this.mod.call("mpc_eckey_mp_get_x_share", keyRef, xCmem);
    const xShare = this.mod.readCmem(xCmem);
    this.mod.freeCmem(xCmem);

    this.mod.free(keyRef);
    return { partyName, publicKey, xShare };
  }

  serializeEcKeyMp(key: EcKeyMpHandle): Uint8Array[] {
    const keyRef = this.mod.allocRef();
    this.mod.setPointer(keyRef, key as unknown as number);
    const cmemsSize = this.mod.POINTER_SIZE * 3;
    const serCmems = this.mod.malloc(cmemsSize);

    const err = this.mod.call("serialize_mpc_eckey_mp", keyRef, serCmems);
    const result = err === 0 ? this.mod.readCmems(serCmems) : [];
    this.mod.freeCmems(serCmems);
    this.mod.free(keyRef);
    checkError(err, "serializeEcKeyMp");
    return result;
  }

  deserializeEcKeyMp(data: Uint8Array[]): EcKeyMpHandle {
    const serCmems = this.mod.writeCmems(data);
    const keyRef = this.mod.allocRef();

    const err = this.mod.call("wasm_deserialize_mpc_eckey_mp", serCmems, keyRef);
    const keyHandle = this.mod.readRef(keyRef) as unknown as EcKeyMpHandle;
    this.mod.free(keyRef);
    this.mod.freeCmems(serCmems);
    checkError(err, "deserializeEcKeyMp");
    return keyHandle;
  }

  freeEcKeyMp(key: EcKeyMpHandle): void {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, key as unknown as number);
    this.mod.call("wasm_free_mpc_eckey_mp", refPtr);
    this.mod.free(refPtr);
  }

  // =========================================================================
  // ECDSA Multi-Party Signing
  // =========================================================================

  async ecdsaMpSign(
    transport: DataTransport,
    partyCount: number,
    partyIndex: number,
    partyNames: string[],
    key: EcKeyMpHandle,
    message: Uint8Array,
    sigReceiver: number,
  ): Promise<Uint8Array> {
    const transportId = this.registerTransport(transport);
    const { arrayPtr: namesArray, namePtrs } = this.mod.allocPartyNames(partyNames);

    let jobPtr = 0;
    try {
      jobPtr = this.mod.call(
        "wasm_new_job_mp", transportId, partyCount, partyIndex, namesArray, partyNames.length,
      );
      if (!jobPtr) throw new CbMpcError(-1, "ecdsaMpSign: failed to create job");

      const keyRef = this.mod.allocRef();
      this.mod.setPointer(keyRef, key as unknown as number);
      const msgCmem = this.mod.writeCmem(message);
      const sigCmem = this.mod.malloc(this.mod.CMEM_SIZE);

      const err = await this.mod.callAsync(
        "wasm_mpc_ecdsampc_sign", jobPtr, keyRef, msgCmem, sigReceiver, sigCmem,
      );

      const sig = err === 0 ? this.mod.readCmem(sigCmem) : new Uint8Array(0);

      this.mod.free(keyRef);
      this.mod.freeCmem(msgCmem);
      this.mod.freeCmem(sigCmem);

      checkError(err, "ecdsaMpSign");
      return sig;
    } finally {
      if (jobPtr) this.mod.call("free_job_mp", jobPtr);
      for (const p of namePtrs) this.mod.free(p);
      this.mod.free(namesArray);
      this.unregisterTransport(transportId);
    }
  }

  // =========================================================================
  // EdDSA Multi-Party Signing
  // =========================================================================

  async eddsaMpSign(
    transport: DataTransport,
    partyCount: number,
    partyIndex: number,
    partyNames: string[],
    key: EcKeyMpHandle,
    message: Uint8Array,
    sigReceiver: number,
  ): Promise<Uint8Array> {
    const transportId = this.registerTransport(transport);
    const { arrayPtr: namesArray, namePtrs } = this.mod.allocPartyNames(partyNames);

    let jobPtr = 0;
    try {
      jobPtr = this.mod.call(
        "wasm_new_job_mp", transportId, partyCount, partyIndex, namesArray, partyNames.length,
      );
      if (!jobPtr) throw new CbMpcError(-1, "eddsaMpSign: failed to create job");

      const keyRef = this.mod.allocRef();
      this.mod.setPointer(keyRef, key as unknown as number);
      const msgCmem = this.mod.writeCmem(message);
      const sigCmem = this.mod.malloc(this.mod.CMEM_SIZE);

      const err = await this.mod.callAsync(
        "wasm_mpc_eddsampc_sign", jobPtr, keyRef, msgCmem, sigReceiver, sigCmem,
      );

      const sig = err === 0 ? this.mod.readCmem(sigCmem) : new Uint8Array(0);

      this.mod.free(keyRef);
      this.mod.freeCmem(msgCmem);
      this.mod.freeCmem(sigCmem);

      checkError(err, "eddsaMpSign");
      return sig;
    } finally {
      if (jobPtr) this.mod.call("free_job_mp", jobPtr);
      for (const p of namePtrs) this.mod.free(p);
      this.mod.free(namesArray);
      this.unregisterTransport(transportId);
    }
  }

  // =========================================================================
  // Zero-Knowledge Proofs
  // =========================================================================

  async zkDlProve(
    Q: PointHandle,
    witness: Uint8Array,
    sessionId: Uint8Array,
    aux: number,
  ): Promise<Uint8Array> {
    const [auxLo, auxHi] = splitU64(aux); // validate before allocating
    const qRef = this.mod.allocRef();
    this.mod.setPointer(qRef, Q as unknown as number);
    const wCmem = this.mod.writeCmem(witness);
    const sidCmem = this.mod.writeCmem(sessionId);
    const proofCmem = this.mod.malloc(this.mod.CMEM_SIZE);

    const err = await this.mod.callAsync("wasm_zk_dl_prove", qRef, wCmem, sidCmem, auxLo, auxHi, proofCmem);
    const proof = err === 0 ? this.mod.readCmem(proofCmem) : new Uint8Array(0);

    this.mod.free(qRef);
    this.mod.freeCmem(wCmem);
    this.mod.freeCmem(sidCmem);
    this.mod.freeCmem(proofCmem);

    checkError(err, "zkDlProve");
    return proof;
  }

  async zkDlVerify(
    Q: PointHandle,
    proof: Uint8Array,
    sessionId: Uint8Array,
    aux: number,
  ): Promise<boolean> {
    const [auxLo, auxHi] = splitU64(aux); // validate before allocating
    const qRef = this.mod.allocRef();
    this.mod.setPointer(qRef, Q as unknown as number);
    const proofCmem = this.mod.writeCmem(proof);
    const sidCmem = this.mod.writeCmem(sessionId);

    const result = await this.mod.callAsync("wasm_zk_dl_verify", qRef, proofCmem, sidCmem, auxLo, auxHi);

    this.mod.free(qRef);
    this.mod.freeCmem(proofCmem);
    this.mod.freeCmem(sidCmem);

    return result === 0;
  }

  // =========================================================================
  // PVE (publicly verifiable encryption) — batch, single recipient,
  // cbmpc's built-in ECIES (P-256) base PKE
  // =========================================================================

  /** Generate a PVE recipient keypair. `dk` is secret; `ek` can be public. */
  pveGenerateKeypair(): { ek: Uint8Array; dk: Uint8Array } {
    const ekCmem = this.mod.malloc(this.mod.CMEM_SIZE);
    const dkCmem = this.mod.malloc(this.mod.CMEM_SIZE);
    const err = this.mod.call("pve_generate_ecies_p256_keypair", ekCmem, dkCmem);
    const ek = err === 0 ? this.mod.readCmem(ekCmem) : new Uint8Array(0);
    const dk = err === 0 ? this.mod.readCmem(dkCmem) : new Uint8Array(0);
    this.mod.freeCmem(ekCmem);
    this.mod.freeCmem(dkCmem);
    checkError(err, "pveGenerateKeypair");
    return { ek, dk };
  }

  /**
   * Encrypt scalars `xs` (big-endian) on `curveCode` to `ek`, bound to `label`.
   * Anyone holding `ek`, `label` and the public points x_i*G can check the
   * ciphertext with {@link pveBatchVerify} without decrypting it.
   */
  pveBatchEncrypt(curveCode: number, ek: Uint8Array, label: Uint8Array, xs: Uint8Array[]): Uint8Array {
    const ekCmem = this.mod.writeCmem(ek);
    const labelCmem = this.mod.writeCmem(label);
    const xsCmems = this.mod.writeCmems(xs);
    const ctCmem = this.mod.malloc(this.mod.CMEM_SIZE);
    const err = this.mod.call("wasm_pve_batch_encrypt", curveCode, ekCmem, labelCmem, xsCmems, ctCmem);
    const ct = err === 0 ? this.mod.readCmem(ctCmem) : new Uint8Array(0);
    this.mod.freeCmem(ekCmem);
    this.mod.freeCmem(labelCmem);
    this.mod.freeCmems(xsCmems);
    this.mod.freeCmem(ctCmem);
    checkError(err, "pveBatchEncrypt");
    return ct;
  }

  /**
   * True when `ciphertext` encrypts scalars x_i with x_i*G == Qs[i] under `ek` and `label`.
   * Qs[i] may come from {@link pointToBytes} or be a raw compressed encoding (SEC1 / Ed25519).
   */
  pveBatchVerify(
    curveCode: number,
    ek: Uint8Array,
    ciphertext: Uint8Array,
    Qs: Uint8Array[],
    label: Uint8Array,
  ): boolean {
    const ekCmem = this.mod.writeCmem(ek);
    const ctCmem = this.mod.writeCmem(ciphertext);
    const qsCmems = this.mod.writeCmems(Qs);
    const labelCmem = this.mod.writeCmem(label);
    const err = this.mod.call("wasm_pve_batch_verify", curveCode, ekCmem, ctCmem, qsCmems, labelCmem);
    this.mod.freeCmem(ekCmem);
    this.mod.freeCmem(ctCmem);
    this.mod.freeCmems(qsCmems);
    this.mod.freeCmem(labelCmem);
    return err === 0;
  }

  /** Decrypt a batch ciphertext. Does not verify it first; call {@link pveBatchVerify} when that matters. */
  pveBatchDecrypt(
    curveCode: number,
    dk: Uint8Array,
    ek: Uint8Array,
    ciphertext: Uint8Array,
    label: Uint8Array,
  ): Uint8Array[] {
    const dkCmem = this.mod.writeCmem(dk);
    const ekCmem = this.mod.writeCmem(ek);
    const ctCmem = this.mod.writeCmem(ciphertext);
    const labelCmem = this.mod.writeCmem(label);
    const xsCmems = this.mod.malloc(this.mod.POINTER_SIZE * 3);
    const err = this.mod.call("wasm_pve_batch_decrypt", curveCode, dkCmem, ekCmem, ctCmem, labelCmem, xsCmems);
    const xs = err === 0 ? this.mod.readCmems(xsCmems) : [];
    this.mod.freeCmem(dkCmem);
    this.mod.freeCmem(ekCmem);
    this.mod.freeCmem(ctCmem);
    this.mod.freeCmem(labelCmem);
    this.mod.freeCmems(xsCmems);
    checkError(err, "pveBatchDecrypt");
    return xs;
  }

  // =========================================================================
  // Access-structure (AC) keys: dkg / refresh / sign / reshare
  // =========================================================================
  // Key blobs are the library's v2 AC blobs (same bytes as the C API). ECDSA-MP on secp256k1 / P-256,
  // EdDSA-MP on Ed25519. Blobs and additive shares are secret key material.

  /** Runs `fn(jobPtr)` with an MP job over `partyNames` (this party at `partyIndex`). */
  private async withJobMp<T>(
    what: string,
    transport: DataTransport,
    partyIndex: number,
    partyNames: string[],
    fn: (jobPtr: number) => Promise<T>,
  ): Promise<T> {
    const transportId = this.registerTransport(transport);
    const { arrayPtr: namesArray, namePtrs } = this.mod.allocPartyNames(partyNames);
    let jobPtr = 0;
    try {
      jobPtr = this.mod.call(
        "wasm_new_job_mp", transportId, partyNames.length, partyIndex, namesArray, partyNames.length,
      );
      if (!jobPtr) throw new CbMpcError(-1, `${what}: failed to create job`);
      return await fn(jobPtr);
    } finally {
      if (jobPtr) this.mod.call("free_job_mp", jobPtr);
      for (const p of namePtrs) this.mod.free(p);
      this.mod.free(namesArray);
      this.unregisterTransport(transportId);
    }
  }

  /** Calls `fnName(...args, outCmem)` and returns the output buffer; frees every input cmem/cmems. */
  private async callForCmem(
    fnName: string,
    args: number[],
    cmems: number[],
    cmemsList: number[],
  ): Promise<Uint8Array> {
    const out = this.mod.malloc(this.mod.CMEM_SIZE);
    try {
      const err = await this.mod.callAsync(fnName, ...args, out);
      const result = err === 0 ? this.mod.readCmem(out) : new Uint8Array(0);
      checkError(err, fnName);
      return result;
    } finally {
      this.mod.freeCmem(out);
      for (const c of cmems) this.mod.freeCmem(c);
      for (const c of cmemsList) this.mod.freeCmems(c);
    }
  }

  private encodeNames(names: string[]): Uint8Array[] {
    return names.map((n) => new TextEncoder().encode(n));
  }

  /**
   * Access-structure DKG. All of `partyNames` must be online; `quorumNames` (satisfying `accessStructure`)
   * contribute randomness. Returns this party's key blob.
   */
  async dkgAc(
    transport: DataTransport,
    partyIndex: number,
    partyNames: string[],
    curveCode: number,
    accessStructure: AccessStructure,
    quorumNames: string[],
  ): Promise<Uint8Array> {
    const acBytes = encodeAccessStructure(accessStructure); // may throw: before any allocation
    return this.withJobMp("dkgAc", transport, partyIndex, partyNames, (job) => {
      const ac = this.mod.writeCmem(acBytes);
      const quorum = this.mod.writeCmems(this.encodeNames(quorumNames));
      return this.callForCmem("wasm_mpc_ac_dkg", [job, curveCode, ac, quorum], [ac], [quorum]);
    });
  }

  /** Re-randomize all shares (same public key). All of `partyNames` must be online. */
  async refreshAc(
    transport: DataTransport,
    partyIndex: number,
    partyNames: string[],
    keyBlob: Uint8Array,
    accessStructure: AccessStructure,
    quorumNames: string[],
  ): Promise<Uint8Array> {
    const acBytes = encodeAccessStructure(accessStructure); // may throw: before any allocation
    return this.withJobMp("refreshAc", transport, partyIndex, partyNames, (job) => {
      const key = this.mod.writeCmem(keyBlob);
      const ac = this.mod.writeCmem(acBytes);
      const quorum = this.mod.writeCmems(this.encodeNames(quorumNames));
      return this.callForCmem("wasm_mpc_ac_refresh", [job, key, ac, quorum], [key, ac], [quorum]);
    });
  }

  /**
   * Sign with a qualifying set of online parties (`partyNames` = the signers only). Returns the signature
   * (DER for ECDSA, 64 bytes for EdDSA) on `sigReceiver`; other parties get an empty array.
   */
  async signAc(
    transport: DataTransport,
    partyIndex: number,
    partyNames: string[],
    keyBlob: Uint8Array,
    accessStructure: AccessStructure,
    message: Uint8Array,
    sigReceiver: number,
  ): Promise<Uint8Array> {
    const acBytes = encodeAccessStructure(accessStructure); // may throw: before any allocation
    return this.withJobMp("signAc", transport, partyIndex, partyNames, (job) => {
      const key = this.mod.writeCmem(keyBlob);
      const ac = this.mod.writeCmem(acBytes);
      const msg = this.mod.writeCmem(message);
      return this.callForCmem("wasm_mpc_ac_sign", [job, key, ac, msg, sigReceiver], [key, ac, msg], []);
    });
  }

  /**
   * Reshare a key to `newAccessStructure`, keeping `publicKey` (compressed, or SEC1 as returned by the 2P key
   * getters). `dealerNames` hold an additive sharing of the key: both shares of a 2P key (`xShare` from
   * ecdsa2pKeyInfo / ecKey2pInfo) or {@link acToAdditiveShare} outputs for one quorum. Dealers pass their share,
   * other parties pass null. All of `partyNames` must be online and each is a dealer, a new party, or both.
   * Returns the new key blob, or an empty array for a dealer outside the new structure.
   *
   * Every party must take `publicKey` from its own trusted record (its own 2P key / AC blob, or the wallet's known
   * public key), never from a peer or relay message.
   * Old shares are not revoked. Treat the new generation as live only after every party reported success; then
   * delete the old shares and run refreshAc.
   */
  async reshareFromAdditive(
    transport: DataTransport,
    partyIndex: number,
    partyNames: string[],
    curveCode: number,
    publicKey: Uint8Array,
    dealerNames: string[],
    additiveShare: Uint8Array | null,
    newAccessStructure: AccessStructure,
  ): Promise<Uint8Array> {
    const acBytes = encodeAccessStructure(newAccessStructure); // may throw: before any allocation
    return this.withJobMp("reshareFromAdditive", transport, partyIndex, partyNames, (job) => {
      const Q = this.mod.writeCmem(publicKey);
      const dealers = this.mod.writeCmems(this.encodeNames(dealerNames));
      const x = this.mod.writeCmem(additiveShare ?? new Uint8Array(0));
      const ac = this.mod.writeCmem(acBytes);
      return this.callForCmem(
        "wasm_mpc_ac_reshare_from_additive", [job, curveCode, Q, dealers, x, ac], [Q, x, ac], [dealers],
      );
    });
  }

  /** This party's additive share for exactly `quorumNames`, a minimal qualifying set (Lagrange-weighted). Secret. */
  acToAdditiveShare(keyBlob: Uint8Array, accessStructure: AccessStructure, quorumNames: string[]): Uint8Array {
    const acBytes = encodeAccessStructure(accessStructure); // may throw: before any allocation
    const key = this.mod.writeCmem(keyBlob);
    const ac = this.mod.writeCmem(acBytes);
    const quorum = this.mod.writeCmems(this.encodeNames(quorumNames));
    const out = this.mod.malloc(this.mod.CMEM_SIZE);
    try {
      const err = this.mod.call("wasm_mpc_ac_to_additive_share", key, ac, quorum, out);
      const x = err === 0 ? this.mod.readCmem(out) : new Uint8Array(0);
      checkError(err, "acToAdditiveShare");
      return x;
    } finally {
      this.mod.freeCmem(out);
      this.mod.freeCmem(key);
      this.mod.freeCmem(ac);
      this.mod.freeCmems(quorum);
    }
  }

  /** Compressed public key and this party's compressed public share. */
  acKeyInfo(keyBlob: Uint8Array): { publicKey: Uint8Array; publicShare: Uint8Array } {
    const key = this.mod.writeCmem(keyBlob);
    const q = this.mod.malloc(this.mod.CMEM_SIZE);
    const qi = this.mod.malloc(this.mod.CMEM_SIZE);
    try {
      const err = this.mod.call("wasm_mpc_ac_key_info", key, q, qi);
      const publicKey = err === 0 ? this.mod.readCmem(q) : new Uint8Array(0);
      const publicShare = err === 0 ? this.mod.readCmem(qi) : new Uint8Array(0);
      checkError(err, "acKeyInfo");
      return { publicKey, publicShare };
    } finally {
      this.mod.freeCmem(key);
      this.mod.freeCmem(q);
      this.mod.freeCmem(qi);
    }
  }

  // =========================================================================
  // Agree Random (Two-Party)
  // =========================================================================

  async agreeRandom(
    transport: DataTransport,
    partyIndex: number,
    partyNames: [string, string],
    bitLen: number,
  ): Promise<Uint8Array> {
    const transportId = this.registerTransport(transport);
    const name0 = this.mod.allocString(partyNames[0]);
    const name1 = this.mod.allocString(partyNames[1]);

    let jobPtr = 0;
    try {
      jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, "agreeRandom: failed to create job");

      const outCmem = this.mod.malloc(this.mod.CMEM_SIZE);
      const err = await this.mod.callAsync("mpc_agree_random", jobPtr, bitLen, outCmem);
      const result = err === 0 ? this.mod.readCmem(outCmem) : new Uint8Array(0);

      this.mod.freeCmem(outCmem);

      checkError(err, "agreeRandom");
      return result;
    } finally {
      if (jobPtr) this.mod.call("free_job_2p", jobPtr);
      this.mod.free(name0);
      this.mod.free(name1);
      this.unregisterTransport(transportId);
    }
  }

  // =========================================================================
  // HD keysets (2-party ECDSA / EdDSA) -- see capi/hd_keyset.h
  //
  // A keyset is one DKG; keys for any path are derived on demand (nothing per
  // path needs storing). Hardened path = account label (2-party VRF step,
  // not BIP32 hardened); non-hardened paths = standard BIP32 below it.
  // =========================================================================

  /** Run a protocol call on a fresh 2-party job; frees the job and transport afterwards. */
  private async withJob2p<T>(
    transport: DataTransport,
    partyIndex: number,
    partyNames: [string, string],
    label: string,
    fn: (jobPtr: number) => Promise<T>,
  ): Promise<T> {
    const transportId = this.registerTransport(transport);
    const name0 = this.mod.allocString(partyNames[0]);
    const name1 = this.mod.allocString(partyNames[1]);
    let jobPtr = 0;
    try {
      jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, `${label}: failed to create job`);
      return await fn(jobPtr);
    } finally {
      if (jobPtr) this.mod.call("free_job_2p", jobPtr);
      this.mod.free(name0);
      this.mod.free(name1);
      this.unregisterTransport(transportId);
    }
  }

  /** Big-endian uint32 encoding of a path. */
  private static encodePath(path: number[], nonHardened: boolean, label: string): Uint8Array {
    const out = new Uint8Array(path.length * 4);
    const view = new DataView(out.buffer);
    path.forEach((index, i) => {
      const max = nonHardened ? 0x7fffffff : 0xffffffff;
      if (!Number.isInteger(index) || index < 0 || index > max) {
        throw new RangeError(`${label}: invalid ${nonHardened ? "non-hardened " : ""}path index ${index}`);
      }
      view.setUint32(i * 4, index, false);
    });
    return out;
  }

  /** Call a "(job, handle-in, handle-out)" protocol function and return the new handle. */
  private async hdHandleOp(jobPtr: number, fn: string, label: string, ...args: number[]): Promise<number> {
    const outRef = this.mod.allocRef();
    try {
      const err = await this.mod.callAsync(fn, jobPtr, ...args, outRef);
      const handle = this.mod.readRef(outRef);
      checkError(err, label);
      return handle;
    } finally {
      this.mod.free(outRef);
    }
  }

  private refOf(handle: number): number {
    const ref = this.mod.allocRef();
    this.mod.setPointer(ref, handle);
    return ref;
  }

  private async hdDerive(
    kind: "ecdsa2p" | "eddsa2p",
    jobPtr: number,
    keyset: number,
    hardenedPath: number[],
    nonHardenedPaths: number[][],
    sessionId: Uint8Array,
  ): Promise<number[]> {
    const label = kind === "ecdsa2p" ? "hdEcdsa2pDerive" : "hdEddsa2pDerive";
    if (nonHardenedPaths.length < 1) throw new RangeError(`${label}: need at least one non-hardened path`);
    const hardened = this.mod.writeCmem(CbMpc.encodePath(hardenedPath, false, label));
    const paths = this.mod.writeCmems(nonHardenedPaths.map((p) => CbMpc.encodePath(p, true, label)));
    const sid = this.mod.writeCmem(sessionId);
    const ksRef = this.refOf(keyset);
    const n = nonHardenedPaths.length;
    const outKeys = this.mod.malloc(n * this.mod.POINTER_SIZE);
    try {
      const err = await this.mod.callAsync(`mpc_hd_${kind}_derive`, jobPtr, ksRef, hardened, paths, sid, outKeys, n);
      const handles = Array.from({ length: n }, (_, i) => this.mod.getPointer(outKeys + i * this.mod.POINTER_SIZE));
      checkError(err, label);
      return handles;
    } finally {
      this.mod.free(outKeys);
      this.mod.free(ksRef);
      this.mod.freeCmem(sid);
      this.mod.freeCmems(paths);
      this.mod.freeCmem(hardened);
    }
  }

  private async hdAccountNode(
    kind: "ecdsa2p" | "eddsa2p",
    jobPtr: number,
    keyset: number,
    hardenedPath: number[],
    sessionId: Uint8Array,
  ): Promise<HdAccountNode> {
    const label = kind === "ecdsa2p" ? "hdEcdsa2pAccountNode" : "hdEddsa2pAccountNode";
    const hardened = this.mod.writeCmem(CbMpc.encodePath(hardenedPath, false, label));
    const sid = this.mod.writeCmem(sessionId);
    const ksRef = this.refOf(keyset);
    const pubOut = this.mod.malloc(this.mod.CMEM_SIZE);
    const ccOut = this.mod.malloc(this.mod.CMEM_SIZE);
    try {
      const err = await this.mod.callAsync(`mpc_hd_${kind}_account_node`, jobPtr, ksRef, hardened, sid, pubOut, ccOut);
      const publicKey = this.mod.readCmem(pubOut);
      const chainCode = this.mod.readCmem(ccOut);
      checkError(err, label);
      return { publicKey, chainCode };
    } finally {
      this.mod.freeCmem(pubOut);
      this.mod.freeCmem(ccOut);
      this.mod.free(ksRef);
      this.mod.freeCmem(sid);
      this.mod.freeCmem(hardened);
    }
  }

  private hdKeysetInfo(kind: "ecdsa2p" | "eddsa2p", keyset: number): HdKeysetInfo {
    const ref = this.refOf(keyset);
    try {
      const roleIndex = this.mod.call(`mpc_hd_${kind}_get_role_index`, ref);
      const curveCode = this.mod.call(`mpc_hd_${kind}_get_curve_code`, ref);
      if (roleIndex < 0 || curveCode < 0) throw new CbMpcError(-1, `hd keyset info: invalid handle`);
      const publicKey = this.extractPublicKey(`mpc_hd_${kind}_get_Q`, ref);
      return { roleIndex, curveCode, publicKey };
    } finally {
      this.mod.free(ref);
    }
  }

  private hdSerialize(kind: "ecdsa2p" | "eddsa2p", keyset: number): Uint8Array[] {
    const ref = this.refOf(keyset);
    const ser = this.mod.malloc(this.mod.POINTER_SIZE * 3);
    try {
      const err = this.mod.call(`serialize_mpc_hd_${kind}`, ref, ser);
      const result = err === 0 ? this.mod.readCmems(ser) : [];
      checkError(err, `serialize hd ${kind}`);
      return result;
    } finally {
      this.mod.freeCmems(ser);
      this.mod.free(ref);
    }
  }

  private hdDeserialize(kind: "ecdsa2p" | "eddsa2p", data: Uint8Array[]): number {
    const ser = this.mod.writeCmems(data);
    const out = this.mod.allocRef();
    try {
      const err = this.mod.call(`deserialize_mpc_hd_${kind}`, ser, out);
      const handle = this.mod.readRef(out);
      checkError(err, `deserialize hd ${kind}`);
      return handle;
    } finally {
      this.mod.free(out);
      this.mod.freeCmems(ser);
    }
  }

  private hdFree(kind: "ecdsa2p" | "eddsa2p", keyset: number): void {
    const ref = this.refOf(keyset);
    this.mod.call(`free_mpc_hd_${kind}`, ref);
    this.mod.free(ref);
  }

  // ---- ECDSA-2P keysets ----------------------------------------------------

  /** Create an ECDSA HD keyset (secp256k1 or P-256). One-time, like ecdsa2pDkg. */
  async hdEcdsa2pDkg(
    transport: DataTransport, partyIndex: number, partyNames: [string, string], curveCode: number,
  ): Promise<HdEcdsa2pKeysetHandle> {
    return this.withJob2p(transport, partyIndex, partyNames, "hdEcdsa2pDkg", async (job) =>
      (await this.hdHandleOp(job, "mpc_hd_ecdsa2p_dkg", "hdEcdsa2pDkg", curveCode)) as HdEcdsa2pKeysetHandle);
  }

  /**
   * Turn an existing ECDSA-2P key into an HD keyset (runs a small VRF-key DKG
   * only). The root public key, and so the existing address, is unchanged; both
   * parties must pass their shares of the same key.
   */
  async hdEcdsa2pFromKey(
    transport: DataTransport, partyIndex: number, partyNames: [string, string], key: Ecdsa2pKeyHandle,
  ): Promise<HdEcdsa2pKeysetHandle> {
    return this.withJob2p(transport, partyIndex, partyNames, "hdEcdsa2pFromKey", async (job) => {
      const keyRef = this.refOf(key as unknown as number);
      try {
        return (await this.hdHandleOp(job, "mpc_hd_ecdsa2p_from_key", "hdEcdsa2pFromKey", keyRef)) as HdEcdsa2pKeysetHandle;
      } finally {
        this.mod.free(keyRef);
      }
    });
  }

  /** Refresh a keyset (both signing and VRF shares). Public keys and all derived addresses stay the same. */
  async hdEcdsa2pRefresh(
    transport: DataTransport, partyIndex: number, partyNames: [string, string], keyset: HdEcdsa2pKeysetHandle,
  ): Promise<HdEcdsa2pKeysetHandle> {
    return this.withJob2p(transport, partyIndex, partyNames, "hdEcdsa2pRefresh", async (job) => {
      const ref = this.refOf(keyset as unknown as number);
      try {
        return (await this.hdHandleOp(job, "mpc_hd_ecdsa2p_refresh", "hdEcdsa2pRefresh", ref)) as HdEcdsa2pKeysetHandle;
      } finally {
        this.mod.free(ref);
      }
    });
  }

  /**
   * Derive ECDSA-2P keys for `hardenedPath` (e.g. [44', 0', account']) and each
   * non-hardened path below it (e.g. [[0, 5], [1, 2]]) in one protocol run.
   * The returned handles are ordinary Ecdsa2pKeyHandle (sign with ecdsa2pSign,
   * free with freeEcdsa2pKey). Indices in `nonHardenedPaths` must be < 2^31.
   */
  async hdEcdsa2pDerive(
    transport: DataTransport, partyIndex: number, partyNames: [string, string], keyset: HdEcdsa2pKeysetHandle,
    hardenedPath: number[], nonHardenedPaths: number[][], sessionId: Uint8Array = new Uint8Array(0),
  ): Promise<Ecdsa2pKeyHandle[]> {
    return this.withJob2p(transport, partyIndex, partyNames, "hdEcdsa2pDerive", async (job) =>
      (await this.hdDerive("ecdsa2p", job, keyset as unknown as number, hardenedPath, nonHardenedPaths, sessionId)) as
        unknown as Ecdsa2pKeyHandle[]);
  }

  /** Account node (xpub material) for `hardenedPath`; see HdAccountNode. */
  async hdEcdsa2pAccountNode(
    transport: DataTransport, partyIndex: number, partyNames: [string, string], keyset: HdEcdsa2pKeysetHandle,
    hardenedPath: number[], sessionId: Uint8Array = new Uint8Array(0),
  ): Promise<HdAccountNode> {
    return this.withJob2p(transport, partyIndex, partyNames, "hdEcdsa2pAccountNode", (job) =>
      this.hdAccountNode("ecdsa2p", job, keyset as unknown as number, hardenedPath, sessionId));
  }

  hdEcdsa2pKeysetInfo(keyset: HdEcdsa2pKeysetHandle): HdKeysetInfo {
    return this.hdKeysetInfo("ecdsa2p", keyset as unknown as number);
  }

  serializeHdEcdsa2p(keyset: HdEcdsa2pKeysetHandle): Uint8Array[] {
    return this.hdSerialize("ecdsa2p", keyset as unknown as number);
  }

  deserializeHdEcdsa2p(data: Uint8Array[]): HdEcdsa2pKeysetHandle {
    return this.hdDeserialize("ecdsa2p", data) as HdEcdsa2pKeysetHandle;
  }

  freeHdEcdsa2p(keyset: HdEcdsa2pKeysetHandle): void {
    this.hdFree("ecdsa2p", keyset as unknown as number);
  }

  // ---- EdDSA-2P keysets (Ed25519) -------------------------------------------

  async hdEddsa2pDkg(
    transport: DataTransport, partyIndex: number, partyNames: [string, string], curveCode: number,
  ): Promise<HdEddsa2pKeysetHandle> {
    return this.withJob2p(transport, partyIndex, partyNames, "hdEddsa2pDkg", async (job) =>
      (await this.hdHandleOp(job, "mpc_hd_eddsa2p_dkg", "hdEddsa2pDkg", curveCode)) as HdEddsa2pKeysetHandle);
  }

  /** Turn an existing EdDSA-2P key (EcKey2pHandle, Ed25519) into an HD keyset; root public key unchanged. */
  async hdEddsa2pFromKey(
    transport: DataTransport, partyIndex: number, partyNames: [string, string], key: EcKey2pHandle,
  ): Promise<HdEddsa2pKeysetHandle> {
    return this.withJob2p(transport, partyIndex, partyNames, "hdEddsa2pFromKey", async (job) => {
      const keyRef = this.refOf(key as unknown as number);
      try {
        return (await this.hdHandleOp(job, "mpc_hd_eddsa2p_from_key", "hdEddsa2pFromKey", keyRef)) as HdEddsa2pKeysetHandle;
      } finally {
        this.mod.free(keyRef);
      }
    });
  }

  async hdEddsa2pRefresh(
    transport: DataTransport, partyIndex: number, partyNames: [string, string], keyset: HdEddsa2pKeysetHandle,
  ): Promise<HdEddsa2pKeysetHandle> {
    return this.withJob2p(transport, partyIndex, partyNames, "hdEddsa2pRefresh", async (job) => {
      const ref = this.refOf(keyset as unknown as number);
      try {
        return (await this.hdHandleOp(job, "mpc_hd_eddsa2p_refresh", "hdEddsa2pRefresh", ref)) as HdEddsa2pKeysetHandle;
      } finally {
        this.mod.free(ref);
      }
    });
  }

  /** Derive EdDSA-2P keys (EcKey2pHandle; sign with schnorr2pEddsaSign). */
  async hdEddsa2pDerive(
    transport: DataTransport, partyIndex: number, partyNames: [string, string], keyset: HdEddsa2pKeysetHandle,
    hardenedPath: number[], nonHardenedPaths: number[][], sessionId: Uint8Array = new Uint8Array(0),
  ): Promise<EcKey2pHandle[]> {
    return this.withJob2p(transport, partyIndex, partyNames, "hdEddsa2pDerive", async (job) =>
      (await this.hdDerive("eddsa2p", job, keyset as unknown as number, hardenedPath, nonHardenedPaths, sessionId)) as
        unknown as EcKey2pHandle[]);
  }

  /** Account node for Ed25519 (non-standard; only for use with this library). */
  async hdEddsa2pAccountNode(
    transport: DataTransport, partyIndex: number, partyNames: [string, string], keyset: HdEddsa2pKeysetHandle,
    hardenedPath: number[], sessionId: Uint8Array = new Uint8Array(0),
  ): Promise<HdAccountNode> {
    return this.withJob2p(transport, partyIndex, partyNames, "hdEddsa2pAccountNode", (job) =>
      this.hdAccountNode("eddsa2p", job, keyset as unknown as number, hardenedPath, sessionId));
  }

  hdEddsa2pKeysetInfo(keyset: HdEddsa2pKeysetHandle): HdKeysetInfo {
    return this.hdKeysetInfo("eddsa2p", keyset as unknown as number);
  }

  serializeHdEddsa2p(keyset: HdEddsa2pKeysetHandle): Uint8Array[] {
    return this.hdSerialize("eddsa2p", keyset as unknown as number);
  }

  deserializeHdEddsa2p(data: Uint8Array[]): HdEddsa2pKeysetHandle {
    return this.hdDeserialize("eddsa2p", data) as HdEddsa2pKeysetHandle;
  }

  freeHdEddsa2p(keyset: HdEddsa2pKeysetHandle): void {
    this.hdFree("eddsa2p", keyset as unknown as number);
  }
}
