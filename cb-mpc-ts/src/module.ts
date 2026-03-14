/**
 * Backend module interface for cb-mpc.
 *
 * This interface abstracts the low-level operations needed by the CbMpc class,
 * allowing it to work with WASM (Emscripten), bun:ffi, or koffi backends.
 */

import type { DataTransport } from "./types.js";

/**
 * Low-level module interface that backends must implement.
 *
 * All memory operations use numeric pointers. On WASM32 these are 32-bit
 * indices into linear memory; on native 64-bit they are real addresses
 * (safely representable as JS numbers for heap allocations).
 */
export interface CbMpcModule {
  // --- Memory management ---
  malloc(size: number): number;
  free(ptr: number): void;

  /** Allocate and write bytes, returning the pointer. Caller must free. */
  writeBytes(data: Uint8Array): number;
  /** Read `size` bytes from pointer into a new Uint8Array. */
  readBytes(ptr: number, size: number): Uint8Array;

  // --- Scalar value access ---
  getI32(ptr: number): number;
  setI32(ptr: number, value: number): void;
  getPointer(ptr: number): number;
  setPointer(ptr: number, value: number): void;

  // --- String operations ---
  readString(ptr: number): string;
  /** Allocate and write a null-terminated string. Returns pointer. Caller must free. */
  allocString(str: string): number;

  // --- Struct helpers ---
  /** Size of a pointer on this platform (4 for WASM, 8 for native 64-bit). */
  readonly POINTER_SIZE: number;
  /** Size of cmem_t struct. */
  readonly CMEM_SIZE: number;
  /** Size of ref structs (ecurve_ref, ecc_point_ref, etc.). */
  readonly REF_SIZE: number;

  // --- cmem_t helpers ---
  /** Allocate a cmem_t, populate with data, return cmem_t pointer. Caller must freeCmem. */
  writeCmem(data: Uint8Array): number;
  /** Read data from a cmem_t pointer. */
  readCmem(cmemPtr: number): Uint8Array;
  /** Free a cmem_t and its data buffer. */
  freeCmem(cmemPtr: number): void;

  // --- ref struct helpers ---
  /** Allocate space for a ref struct. */
  allocRef(): number;
  /** Read the opaque pointer from a ref struct. */
  readRef(refPtr: number): number;

  // --- cmems_t helpers ---
  /** Write an array of buffers as cmems_t. Returns cmems_t pointer. Caller must freeCmems. */
  writeCmems(buffers: Uint8Array[]): number;
  /** Read a cmems_t into an array of Uint8Arrays. */
  readCmems(cmemsPtr: number): Uint8Array[];
  /** Free a cmems_t and its data/sizes buffers. */
  freeCmems(cmemsPtr: number): void;

  // --- Party name array helpers ---
  /** Allocate an array of C string pointers. Returns { arrayPtr, namePtrs }. Caller must free all. */
  allocPartyNames(names: string[]): { arrayPtr: number; namePtrs: number[] };

  // --- SEC1 point helpers ---
  /** Read a point ref and return SEC1 uncompressed format (04 || x || y). */
  pointToSec1(pointRefPtr: number): Uint8Array;

  // --- C function calls ---
  /** Call a C function synchronously. Returns the integer result. */
  call(name: string, ...args: number[]): number;
  /** Call a C function that may suspend (WASM ASYNCIFY). Native backends may just call synchronously. */
  callAsync(name: string, ...args: number[]): Promise<number>;

  // --- Transport ---
  registerTransport(id: number, transport: DataTransport): void;
  unregisterTransport(id: number): void;

  // --- Lifecycle ---
  /** Seed the PRNG. WASM needs this; native may no-op. */
  seedRandom(entropy: Uint8Array): void;
}
