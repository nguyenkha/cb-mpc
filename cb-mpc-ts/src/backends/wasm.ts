/**
 * WASM (Emscripten) backend for cb-mpc.
 *
 * Wraps the Emscripten-generated module to implement the CbMpcModule interface.
 */

import type { CbMpcModule } from "../module";
import type { CbMpcWasmModule, DataTransport } from "../types";

export class WasmBackend implements CbMpcModule {
  readonly POINTER_SIZE = 4;
  readonly CMEM_SIZE = 8;
  readonly REF_SIZE = 4;

  constructor(private wasm: CbMpcWasmModule) {}

  malloc(size: number): number {
    return this.wasm._malloc(size);
  }

  free(ptr: number): void {
    this.wasm._free(ptr);
  }

  writeBytes(data: Uint8Array): number {
    const ptr = this.wasm._malloc(data.length);
    this.wasm.HEAPU8.set(data, ptr);
    return ptr;
  }

  readBytes(ptr: number, size: number): Uint8Array {
    return new Uint8Array(this.wasm.HEAPU8.buffer, ptr, size).slice();
  }

  getI32(ptr: number): number {
    return this.wasm.getValue(ptr, "i32");
  }

  setI32(ptr: number, value: number): void {
    this.wasm.setValue(ptr, value, "i32");
  }

  getPointer(ptr: number): number {
    return this.wasm.getValue(ptr, "*");
  }

  setPointer(ptr: number, value: number): void {
    this.wasm.setValue(ptr, value, "*");
  }

  readString(ptr: number): string {
    return this.wasm.UTF8ToString(ptr);
  }

  allocString(str: string): number {
    const len = this.wasm.lengthBytesUTF8(str) + 1;
    const ptr = this.wasm._malloc(len);
    this.wasm.stringToUTF8(str, ptr, len);
    return ptr;
  }

  writeCmem(data: Uint8Array): number {
    const cmemPtr = this.wasm._malloc(this.CMEM_SIZE);
    const dataPtr = this.writeBytes(data);
    this.wasm.setValue(cmemPtr, dataPtr, "*");
    this.wasm.setValue(cmemPtr + 4, data.length, "i32");
    return cmemPtr;
  }

  readCmem(cmemPtr: number): Uint8Array {
    const dataPtr = this.wasm.getValue(cmemPtr, "*");
    const size = this.wasm.getValue(cmemPtr + 4, "i32");
    if (!dataPtr || size <= 0) return new Uint8Array(0);
    return this.readBytes(dataPtr, size);
  }

  freeCmem(cmemPtr: number): void {
    const dataPtr = this.wasm.getValue(cmemPtr, "*");
    if (dataPtr) this.wasm._free(dataPtr);
    this.wasm._free(cmemPtr);
  }

  allocRef(): number {
    return this.wasm._malloc(this.REF_SIZE);
  }

  readRef(refPtr: number): number {
    return this.wasm.getValue(refPtr, "*");
  }

  writeCmems(buffers: Uint8Array[]): number {
    const count = buffers.length;
    let totalSize = 0;
    for (const b of buffers) totalSize += b.length;

    const dataPtr = this.wasm._malloc(totalSize);
    const sizesPtr = this.wasm._malloc(count * 4);
    let offset = 0;
    for (let i = 0; i < count; i++) {
      this.wasm.HEAPU8.set(buffers[i], dataPtr + offset);
      this.wasm.setValue(sizesPtr + i * 4, buffers[i].length, "i32");
      offset += buffers[i].length;
    }

    const cmemsPtr = this.wasm._malloc(12); // cmems_t = {int, ptr, ptr}
    this.wasm.setValue(cmemsPtr, count, "i32");
    this.wasm.setValue(cmemsPtr + 4, dataPtr, "*");
    this.wasm.setValue(cmemsPtr + 8, sizesPtr, "*");
    return cmemsPtr;
  }

  readCmems(cmemsPtr: number): Uint8Array[] {
    const count = this.wasm.getValue(cmemsPtr, "i32");
    const dataPtr = this.wasm.getValue(cmemsPtr + 4, "*");
    const sizesPtr = this.wasm.getValue(cmemsPtr + 8, "*");
    const result: Uint8Array[] = [];
    let offset = 0;
    for (let i = 0; i < count; i++) {
      const size = this.wasm.getValue(sizesPtr + i * 4, "i32");
      result.push(this.readBytes(dataPtr + offset, size));
      offset += size;
    }
    return result;
  }

  freeCmems(cmemsPtr: number): void {
    const dataPtr = this.wasm.getValue(cmemsPtr + 4, "*");
    const sizesPtr = this.wasm.getValue(cmemsPtr + 8, "*");
    if (dataPtr) this.wasm._free(dataPtr);
    if (sizesPtr) this.wasm._free(sizesPtr);
    this.wasm._free(cmemsPtr);
  }

  allocPartyNames(names: string[]): { arrayPtr: number; namePtrs: number[] } {
    const namePtrs = names.map((n) => this.allocString(n));
    const arrayPtr = this.wasm._malloc(namePtrs.length * this.POINTER_SIZE);
    for (let i = 0; i < namePtrs.length; i++) {
      this.wasm.setValue(arrayPtr + i * this.POINTER_SIZE, namePtrs[i], "*");
    }
    return { arrayPtr, namePtrs };
  }

  pointToSec1(pointRefPtr: number): Uint8Array {
    const xCmem = this.wasm._malloc(this.CMEM_SIZE);
    const yCmem = this.wasm._malloc(this.CMEM_SIZE);
    this.wasm.ccall("wasm_ecc_point_get_x", null, ["number", "number"], [pointRefPtr, xCmem]);
    this.wasm.ccall("wasm_ecc_point_get_y", null, ["number", "number"], [pointRefPtr, yCmem]);
    const x = this.readCmem(xCmem);
    const y = this.readCmem(yCmem);
    this.freeCmem(xCmem);
    this.freeCmem(yCmem);
    const coordSize = Math.max(x.length, y.length);
    const result = new Uint8Array(1 + coordSize * 2);
    result[0] = 0x04;
    result.set(x, 1 + coordSize - x.length);
    result.set(y, 1 + coordSize + coordSize - y.length);
    return result;
  }

  call(name: string, ...args: number[]): number {
    const argTypes = args.map(() => "number");
    return this.wasm.ccall(name, "number", argTypes, args) as number;
  }

  async callAsync(name: string, ...args: number[]): Promise<number> {
    const argTypes = args.map(() => "number");
    return this.wasm.ccall(name, "number", argTypes, args, { async: true }) as Promise<number>;
  }

  registerTransport(id: number, transport: DataTransport): void {
    this.wasm._transportCallbacks[id] = transport;
  }

  unregisterTransport(id: number): void {
    delete this.wasm._transportCallbacks[id];
  }

  seedRandom(entropy: Uint8Array): void {
    const ptr = this.writeBytes(entropy);
    const status = this.wasm._wasm_seed_random(ptr, entropy.length);
    this.wasm._free(ptr);
    if (status !== 1) {
      console.warn("cb-mpc: OpenSSL PRNG seeding may have failed (RAND_status=" + status + ")");
    }
  }
}

/**
 * Create a WASM backend by loading the Emscripten module.
 */
export async function createWasmBackend(
  wasmModuleFactory?: (opts?: object) => Promise<CbMpcWasmModule>,
): Promise<WasmBackend> {
  let factory = wasmModuleFactory;
  if (!factory) {
    // Dynamic import for the Emscripten glue
    // @ts-ignore -- cbmpc.js is generated by Emscripten at build time
    const mod = await import(/* webpackIgnore: true */ "../../cbmpc.js");
    factory = mod.default || mod.createCbMpc || mod;
  }

  const wasm = await factory!();
  (wasm as CbMpcWasmModule)._transportCallbacks = {};

  const backend = new WasmBackend(wasm);

  // Seed PRNG
  const entropy = new Uint8Array(32);
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(entropy);
  } else {
    // @ts-ignore -- crypto is a Node.js built-in
    const { randomFillSync } = await import("crypto");
    randomFillSync(entropy);
  }
  backend.seedRandom(entropy);

  return backend;
}
