/**
 * koffi backend loader for cb-mpc.
 *
 * Uses koffi (npm package) to load the native shared library.
 * Works with Node.js and Bun (koffi uses NAPI).
 *
 * Install: npm install koffi
 */

import type { NativeLib } from "./native.js";
import { NativeBackend, getLibraryPath } from "./native.js";
import { FFI_SIGNATURES, KOFFI_C_TYPE } from "./ffi-signatures.js";

/**
 * Load the koffi module from CommonJS or ESM (this package is ESM, where a
 * global `require` does not exist). The indirection keeps bundlers from
 * resolving koffi statically.
 */
async function loadKoffi(): Promise<any> {
  let _require: ((id: string) => any) | undefined = typeof require !== "undefined" ? require : undefined;
  if (!_require) {
    const moduleName = "node:module";
    const { createRequire } = await import(/* @vite-ignore */ moduleName);
    _require = createRequire(import.meta.url);
  }
  return _require!("koffi");
}

class KoffiLib implements NativeLib {
  private lib: any;
  private koffi: any;
  private fnCache: Map<string, (...args: any[]) => any> = new Map();
  private registeredCallbacks: any[] = [];

  // C prototypes built from the shared signature table (see ffi-signatures.ts).
  private static readonly SIGNATURES: Record<string, string> = Object.fromEntries(
    Object.entries(FFI_SIGNATURES).map(([name, s]) => [
      name,
      `${KOFFI_C_TYPE[s.returns]} ${name}(${s.args.map((a) => KOFFI_C_TYPE[a]).join(", ")})`,
    ]),
  );

  constructor(koffi: any, libPath: string) {
    this.koffi = koffi;
    this.lib = this.koffi.load(libPath);
  }

  fn(name: string): (...args: any[]) => any {
    const cachedFn = this.fnCache.get(name);
    if (cachedFn) return cachedFn;

    const sig = KoffiLib.SIGNATURES[name];
    if (!sig) throw new Error(`Unknown native function: ${name}`);

    const loadedFn = this.lib.func(sig);
    this.fnCache.set(name, loadedFn);
    return loadedFn;
  }

  readBuffer(ptr: number, size: number): Uint8Array {
    if (!ptr || size <= 0) return new Uint8Array(0);
    const koffi = this.koffi;
    // Pointers are plain numbers (intptr_t); decode as a typed uint8 array and copy.
    return new Uint8Array(koffi.decode(ptr, koffi.array("uint8_t", size, "Typed")));
  }

  writeBuffer(ptr: number, data: Uint8Array): void {
    if (!ptr || data.length === 0) return;
    const koffi = this.koffi;
    koffi.encode(ptr, koffi.array("uint8_t", data.length, "Typed"), data);
  }

  readCString(ptr: number): string {
    if (!ptr) return "";
    const koffi = this.koffi;
    return koffi.decode(ptr, "string");
  }

  registerTransportCallbacks(
    send: (transportId: number, receiver: number, dataPtr: number, size: number) => number,
    receive: (transportId: number, sender: number, outDataPtr: number, outSizePtr: number) => number,
    receiveAll: (transportId: number, sendersPtr: number, senderCount: number, outDataPtr: number, outSizesPtr: number, outCountPtr: number) => number,
  ): () => void {
    const koffi = this.koffi;

    // Define callback types
    const sendType = koffi.proto("int native_send_cb(int, int, intptr_t, int)");
    const recvType = koffi.proto("int native_recv_cb(int, int, intptr_t, intptr_t)");
    const recvAllType = koffi.proto("int native_recv_all_cb(int, intptr_t, int, intptr_t, intptr_t, intptr_t)");

    // Register callbacks
    const sendCb = koffi.register(send, koffi.pointer(sendType));
    const recvCb = koffi.register(receive, koffi.pointer(recvType));
    const recvAllCb = koffi.register(receiveAll, koffi.pointer(recvAllType));

    this.registeredCallbacks.push(sendCb, recvCb, recvAllCb);
    // koffi passes registered callbacks as pointer objects; convert to addresses for intptr_t.
    this.fn("native_register_transport")(koffi.address(sendCb), koffi.address(recvCb), koffi.address(recvAllCb));

    return () => {
      koffi.unregister(sendCb);
      koffi.unregister(recvCb);
      koffi.unregister(recvAllCb);
    };
  }

  close(): void {
    for (const cb of this.registeredCallbacks) {
      try {
        this.koffi.unregister(cb);
      } catch {
        // ignore
      }
    }
    this.registeredCallbacks = [];
    // koffi doesn't have an explicit close, library is unloaded on GC
  }
}

/**
 * Create a native backend using koffi.
 * Works with Node.js and Bun (koffi is a NAPI module).
 *
 * Requires: npm install koffi
 */
export async function createKoffiBackend(libPath?: string): Promise<NativeBackend> {
  const path = libPath || getLibraryPath();
  const lib = new KoffiLib(await loadKoffi(), path);
  const backend = new NativeBackend(lib);

  // Seed PRNG
  const entropy = new Uint8Array(32);
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(entropy);
  } else {
    const { randomFillSync } = await import("crypto");
    randomFillSync(entropy);
  }
  backend.seedRandom(entropy);

  return backend;
}
