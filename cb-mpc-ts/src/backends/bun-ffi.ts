/**
 * bun:ffi backend loader for cb-mpc.
 *
 * Uses Bun's built-in FFI to load the native shared library.
 * Only works in the Bun runtime.
 */

import type { NativeLib } from "./native.js";
import { FFI_SIGNATURES } from "./ffi-signatures.js";
import { NativeBackend, getLibraryPath } from "./native.js";

// All exported C functions and their signatures for bun:ffi
// Built from the shared signature table (see ffi-signatures.ts).
const FFI_SYMBOLS = Object.fromEntries(
  Object.entries(FFI_SIGNATURES).map(([name, s]) => [name, { args: [...s.args], returns: s.returns }]),
);

class BunFfiLib implements NativeLib {
  private symbols: Record<string, (...args: any[]) => any>;
  private callbacks: any[] = [];

  constructor(libPath: string) {
    // Use indirect require to prevent bundlers from resolving bun:ffi statically
    const _require = typeof require !== "undefined" ? require : undefined;
    if (!_require) throw new Error("bun:ffi requires the Bun runtime");
    // @ts-ignore - bun:ffi is Bun-only
    const { dlopen, ptr: bunPtr, toArrayBuffer, CString, JSCallback } = _require("bun:ffi");
    const lib = dlopen(libPath, FFI_SYMBOLS);
    this.symbols = lib.symbols;

    // Store bun:ffi utilities for memory operations
    (this as any)._toArrayBuffer = toArrayBuffer;
    (this as any)._CString = CString;
    (this as any)._JSCallback = JSCallback;
    (this as any)._lib = lib;
  }

  fn(name: string): (...args: number[]) => number {
    const sym = this.symbols[name];
    if (!sym) throw new Error(`Unknown native function: ${name}`);
    return sym as (...args: number[]) => number;
  }

  readBuffer(ptr: number, size: number): Uint8Array {
    if (!ptr || size <= 0) return new Uint8Array(0);
    const toArrayBuffer = (this as any)._toArrayBuffer;
    return new Uint8Array(toArrayBuffer(ptr, 0, size)).slice();
  }

  writeBuffer(ptr: number, data: Uint8Array): void {
    if (!ptr || data.length === 0) return;
    // Use a temporary buffer to write to native memory
    const dest = new Uint8Array((this as any)._toArrayBuffer(ptr, 0, data.length));
    dest.set(data);
  }

  readCString(ptr: number): string {
    if (!ptr) return "";
    const CString = (this as any)._CString;
    return new CString(ptr).toString();
  }

  registerTransportCallbacks(
    send: (transportId: number, receiver: number, dataPtr: number, size: number) => number,
    receive: (transportId: number, sender: number, outDataPtr: number, outSizePtr: number) => number,
    receiveAll: (transportId: number, sendersPtr: number, senderCount: number, outDataPtr: number, outSizesPtr: number, outCountPtr: number) => number,
  ): () => void {
    const JSCallback = (this as any)._JSCallback;

    const sendCb = new JSCallback(send, {
      args: ["i32", "i32", "ptr", "i32"],
      returns: "i32",
    });
    const recvCb = new JSCallback(receive, {
      args: ["i32", "i32", "ptr", "ptr"],
      returns: "i32",
    });
    const recvAllCb = new JSCallback(receiveAll, {
      args: ["i32", "ptr", "i32", "ptr", "ptr", "ptr"],
      returns: "i32",
    });

    this.callbacks.push(sendCb, recvCb, recvAllCb);
    this.symbols.native_register_transport(sendCb.ptr, recvCb.ptr, recvAllCb.ptr);

    return () => {
      sendCb.close();
      recvCb.close();
      recvAllCb.close();
    };
  }

  close(): void {
    for (const cb of this.callbacks) {
      if (cb.close) cb.close();
    }
    this.callbacks = [];
    (this as any)._lib?.close();
  }
}

/**
 * Create a native backend using bun:ffi.
 * Only works in the Bun runtime.
 */
export async function createBunFfiBackend(libPath?: string): Promise<NativeBackend> {
  const path = libPath || getLibraryPath();
  const lib = new BunFfiLib(path);
  const backend = new NativeBackend(lib);

  // Seed PRNG with system entropy
  const entropy = new Uint8Array(32);
  globalThis.crypto.getRandomValues(entropy);
  backend.seedRandom(entropy);

  return backend;
}
