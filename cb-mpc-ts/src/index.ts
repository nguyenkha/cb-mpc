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

import debug_module from "debug";
import type { CbMpcModule } from "./module.js";

// Handle both ESM default and CJS module.exports
const createDebug = (typeof debug_module === "function" ? debug_module : (debug_module as any).default) as typeof debug_module;
const debug = createDebug("cb-mpc");
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
} from "./types.js";

export type { CbMpcModule } from "./module.js";
export * from "./types.js";

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
      require.resolve("koffi");
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
    this.mod.call("wasm_new_ecurve", curveCode, outPtr);
    const handle = this.mod.readRef(outPtr);
    this.mod.free(outPtr);
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
    this.mod.call("wasm_ecurve_generator", curveRef, outPtr);
    const handle = this.mod.readRef(outPtr);
    this.mod.free(curveRef);
    this.mod.free(outPtr);
    return handle as unknown as PointHandle;
  }

  curveOrder(curve: CurveHandle): Uint8Array {
    const curveRef = this.mod.allocRef();
    this.mod.setPointer(curveRef, curve as unknown as number);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    this.mod.call("wasm_ecurve_order", curveRef, cmemOut);
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(curveRef);
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
    this.mod.call("wasm_ecurve_random_scalar", curveRef, cmemOut);
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(curveRef);
    return result;
  }

  // =========================================================================
  // Point operations
  // =========================================================================

  pointFromBytes(data: Uint8Array): PointHandle {
    const dataPtr = this.mod.writeBytes(data);
    const outPtr = this.mod.allocRef();
    this.mod.call("wasm_ecc_point_from_bytes", dataPtr, data.length, outPtr);
    const handle = this.mod.readRef(outPtr);
    this.mod.free(outPtr);
    this.mod.free(dataPtr);
    return handle as unknown as PointHandle;
  }

  pointToBytes(point: PointHandle): Uint8Array {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, point as unknown as number);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    this.mod.call("wasm_ecc_point_to_bytes", refPtr, cmemOut);
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(refPtr);
    return result;
  }

  pointGetX(point: PointHandle): Uint8Array {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, point as unknown as number);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    this.mod.call("wasm_ecc_point_get_x", refPtr, cmemOut);
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(refPtr);
    return result;
  }

  pointGetY(point: PointHandle): Uint8Array {
    const refPtr = this.mod.allocRef();
    this.mod.setPointer(refPtr, point as unknown as number);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    this.mod.call("wasm_ecc_point_get_y", refPtr, cmemOut);
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(refPtr);
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
    this.mod.call("wasm_ecc_point_multiply", refPtr, sPtr, scalar.length, outPtr);
    const handle = this.mod.readRef(outPtr);
    this.mod.free(refPtr);
    this.mod.free(sPtr);
    this.mod.free(outPtr);
    return handle as unknown as PointHandle;
  }

  pointAdd(p1: PointHandle, p2: PointHandle): PointHandle {
    const ref1 = this.mod.allocRef();
    const ref2 = this.mod.allocRef();
    this.mod.setPointer(ref1, p1 as unknown as number);
    this.mod.setPointer(ref2, p2 as unknown as number);
    const outPtr = this.mod.allocRef();
    this.mod.call("wasm_ecc_point_add", ref1, ref2, outPtr);
    const handle = this.mod.readRef(outPtr);
    this.mod.free(ref1);
    this.mod.free(ref2);
    this.mod.free(outPtr);
    return handle as unknown as PointHandle;
  }

  pointSubtract(p1: PointHandle, p2: PointHandle): PointHandle {
    const ref1 = this.mod.allocRef();
    const ref2 = this.mod.allocRef();
    this.mod.setPointer(ref1, p1 as unknown as number);
    this.mod.setPointer(ref2, p2 as unknown as number);
    const outPtr = this.mod.allocRef();
    this.mod.call("wasm_ecc_point_subtract", ref1, ref2, outPtr);
    const handle = this.mod.readRef(outPtr);
    this.mod.free(ref1);
    this.mod.free(ref2);
    this.mod.free(outPtr);
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
    this.mod.call("wasm_ecurve_mul_generator", curveRef, sPtr, scalar.length, outPtr);
    const handle = this.mod.readRef(outPtr);
    this.mod.free(curveRef);
    this.mod.free(sPtr);
    this.mod.free(outPtr);
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
    this.mod.call("wasm_bn_add", aPtr, a.length, bPtr, b.length, cmemOut);
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(aPtr);
    this.mod.free(bPtr);
    return result;
  }

  ecModAdd(curve: CurveHandle, a: Uint8Array, b: Uint8Array): Uint8Array {
    const curveRef = this.mod.allocRef();
    this.mod.setPointer(curveRef, curve as unknown as number);
    const aPtr = this.mod.writeBytes(a);
    const bPtr = this.mod.writeBytes(b);
    const cmemOut = this.mod.malloc(this.mod.CMEM_SIZE);
    this.mod.call("wasm_ec_mod_add", curveRef, aPtr, a.length, bPtr, b.length, cmemOut);
    const result = this.mod.readCmem(cmemOut);
    this.mod.freeCmem(cmemOut);
    this.mod.free(curveRef);
    this.mod.free(aPtr);
    this.mod.free(bPtr);
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
    this.mod.call(getQFn, keyRef, qOut);
    const qHandle = this.mod.readRef(qOut);
    this.mod.free(qOut);
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
    this.mod.call(getXShareFn, keyRef, xCmemOut);
    const xShare = this.mod.readCmem(xCmemOut);
    this.mod.freeCmem(xCmemOut);
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

    try {
      const jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, "ecdsa2pDkg: failed to create job");

      const keyRef = this.mod.allocRef();
      const err = await this.mod.callAsync("mpc_ecdsa2p_dkg", jobPtr, curveCode, keyRef);
      const keyHandle = this.mod.readRef(keyRef) as unknown as Ecdsa2pKeyHandle;
      this.mod.free(keyRef);
      this.mod.call("free_job_2p", jobPtr);

      checkError(err, "ecdsa2pDkg");
      return keyHandle;
    } finally {
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

    try {
      const jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, "ecdsa2pSign: failed to create job");

      const sidCmem = this.mod.writeCmem(sessionId);
      const keyRef = this.mod.allocRef();
      this.mod.setPointer(keyRef, key as unknown as number);
      const msgsCmems = this.mod.writeCmems(messages);
      // cmems_t size: int + 2 pointers
      const sigsCmemsSize = 4 + this.mod.POINTER_SIZE * 2;
      const sigsCmems = this.mod.malloc(sigsCmemsSize);

      const err = await this.mod.callAsync(
        "mpc_ecdsa2p_sign", jobPtr, sidCmem, keyRef, msgsCmems, sigsCmems,
      );

      const sigs = err === 0 ? this.mod.readCmems(sigsCmems) : [];

      this.mod.free(keyRef);
      this.mod.freeCmem(sidCmem);
      this.mod.freeCmems(msgsCmems);
      this.mod.freeCmems(sigsCmems);
      this.mod.call("free_job_2p", jobPtr);

      checkError(err, "ecdsa2pSign");
      return sigs;
    } finally {
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

    try {
      const jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, "ecdsa2pRefresh: failed to create job");

      const keyRef = this.mod.allocRef();
      this.mod.setPointer(keyRef, key as unknown as number);
      const newKeyRef = this.mod.allocRef();

      const err = await this.mod.callAsync("mpc_ecdsa2p_refresh", jobPtr, keyRef, newKeyRef);
      const newKey = this.mod.readRef(newKeyRef) as unknown as Ecdsa2pKeyHandle;

      this.mod.free(keyRef);
      this.mod.free(newKeyRef);
      this.mod.call("free_job_2p", jobPtr);

      checkError(err, "ecdsa2pRefresh");
      return newKey;
    } finally {
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
    const cmemsSize = 4 + this.mod.POINTER_SIZE * 2;
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

    const err = this.mod.call("deserialize_mpc_ecdsa2p", serCmems, keyRef);
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

    try {
      const jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, "ecKey2pDkg: failed to create job");

      const keyRef = this.mod.allocRef();
      const err = await this.mod.callAsync("mpc_eckey_2p_dkg", jobPtr, curveCode, keyRef);
      const keyHandle = this.mod.readRef(keyRef) as unknown as EcKey2pHandle;
      this.mod.free(keyRef);
      this.mod.call("free_job_2p", jobPtr);

      checkError(err, "ecKey2pDkg");
      return keyHandle;
    } finally {
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

    try {
      const jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
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
      this.mod.call("free_job_2p", jobPtr);

      checkError(err, "schnorr2pEddsaSign");
      return sig;
    } finally {
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
    const cmemsSize = 4 + this.mod.POINTER_SIZE * 2;
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

    const err = this.mod.call("deserialize_mpc_eckey_2p", serCmems, keyRef);
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

    try {
      const jobPtr = this.mod.call(
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
      this.mod.call("free_job_mp", jobPtr);

      checkError(err, "ecKeyMpDkg");
      return keyHandle;
    } finally {
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

    try {
      const jobPtr = this.mod.call(
        "wasm_new_job_mp", transportId, partyCount, partyIndex, namesArray, partyNames.length,
      );
      if (!jobPtr) throw new CbMpcError(-1, "ecKeyMpRefresh: failed to create job");

      const keyRef = this.mod.allocRef();
      this.mod.setPointer(keyRef, key as unknown as number);
      const sidCmem = this.mod.writeCmem(sessionId);
      const newKeyRef = this.mod.allocRef();

      const err = await this.mod.callAsync("mpc_eckey_mp_refresh", jobPtr, sidCmem, keyRef, newKeyRef);
      const newKey = this.mod.readRef(newKeyRef) as unknown as EcKeyMpHandle;

      this.mod.free(keyRef);
      this.mod.free(newKeyRef);
      this.mod.freeCmem(sidCmem);
      this.mod.call("free_job_mp", jobPtr);

      checkError(err, "ecKeyMpRefresh");
      return newKey;
    } finally {
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
    const cmemsSize = 4 + this.mod.POINTER_SIZE * 2;
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

    const err = this.mod.call("deserialize_mpc_eckey_mp", serCmems, keyRef);
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

    try {
      const jobPtr = this.mod.call(
        "wasm_new_job_mp", transportId, partyCount, partyIndex, namesArray, partyNames.length,
      );
      if (!jobPtr) throw new CbMpcError(-1, "ecdsaMpSign: failed to create job");

      const keyRef = this.mod.allocRef();
      this.mod.setPointer(keyRef, key as unknown as number);
      const msgCmem = this.mod.writeCmem(message);
      const sigCmem = this.mod.malloc(this.mod.CMEM_SIZE);

      const err = await this.mod.callAsync(
        "mpc_ecdsampc_sign", jobPtr, keyRef, msgCmem, sigReceiver, sigCmem,
      );

      const sig = err === 0 ? this.mod.readCmem(sigCmem) : new Uint8Array(0);

      this.mod.free(keyRef);
      this.mod.freeCmem(msgCmem);
      this.mod.freeCmem(sigCmem);
      this.mod.call("free_job_mp", jobPtr);

      checkError(err, "ecdsaMpSign");
      return sig;
    } finally {
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

    try {
      const jobPtr = this.mod.call(
        "wasm_new_job_mp", transportId, partyCount, partyIndex, namesArray, partyNames.length,
      );
      if (!jobPtr) throw new CbMpcError(-1, "eddsaMpSign: failed to create job");

      const keyRef = this.mod.allocRef();
      this.mod.setPointer(keyRef, key as unknown as number);
      const msgCmem = this.mod.writeCmem(message);
      const sigCmem = this.mod.malloc(this.mod.CMEM_SIZE);

      const err = await this.mod.callAsync(
        "mpc_eddsampc_sign", jobPtr, keyRef, msgCmem, sigReceiver, sigCmem,
      );

      const sig = err === 0 ? this.mod.readCmem(sigCmem) : new Uint8Array(0);

      this.mod.free(keyRef);
      this.mod.freeCmem(msgCmem);
      this.mod.freeCmem(sigCmem);
      this.mod.call("free_job_mp", jobPtr);

      checkError(err, "eddsaMpSign");
      return sig;
    } finally {
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
    const qRef = this.mod.allocRef();
    this.mod.setPointer(qRef, Q as unknown as number);
    const wCmem = this.mod.writeCmem(witness);
    const sidCmem = this.mod.writeCmem(sessionId);
    const proofCmem = this.mod.malloc(this.mod.CMEM_SIZE);

    const err = await this.mod.callAsync("zk_dl_prove", qRef, wCmem, sidCmem, aux, proofCmem);
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
    const qRef = this.mod.allocRef();
    this.mod.setPointer(qRef, Q as unknown as number);
    const proofCmem = this.mod.writeCmem(proof);
    const sidCmem = this.mod.writeCmem(sessionId);

    const result = await this.mod.callAsync("zk_dl_verify", qRef, proofCmem, sidCmem, aux);

    this.mod.free(qRef);
    this.mod.freeCmem(proofCmem);
    this.mod.freeCmem(sidCmem);

    return result === 0;
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

    try {
      const jobPtr = this.mod.call("wasm_new_job_2p", transportId, partyIndex, name0, name1);
      if (!jobPtr) throw new CbMpcError(-1, "agreeRandom: failed to create job");

      const outCmem = this.mod.malloc(this.mod.CMEM_SIZE);
      const err = await this.mod.callAsync("mpc_agree_random", jobPtr, bitLen, outCmem);
      const result = err === 0 ? this.mod.readCmem(outCmem) : new Uint8Array(0);

      this.mod.freeCmem(outCmem);
      this.mod.call("free_job_2p", jobPtr);

      checkError(err, "agreeRandom");
      return result;
    } finally {
      this.mod.free(name0);
      this.mod.free(name1);
      this.unregisterTransport(transportId);
    }
  }
}
