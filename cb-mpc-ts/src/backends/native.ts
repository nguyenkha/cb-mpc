/**
 * Native FFI backend for cb-mpc.
 *
 * Loads the precompiled shared library (.dylib/.so) via either:
 *   - bun:ffi (Bun runtime)
 *   - koffi (Node.js runtime)
 *
 * Transport callbacks are synchronous in native mode. For concurrent MPC
 * protocol execution, use worker threads with each party in its own thread.
 */

import type { CbMpcModule } from "../module";
import type { DataTransport } from "../types";
import { resolve, join } from "node:path";

// ---------------------------------------------------------------------------
// FFI library abstraction
// ---------------------------------------------------------------------------

/** A loaded native function that can be called with numeric args. */
export type NativeFn = (...args: number[]) => number;

/** Abstraction over the loaded shared library. */
export interface NativeLib {
  /** Get a function by name. */
  fn(name: string): NativeFn;
  /** Read `size` bytes from a native pointer. */
  readBuffer(ptr: number, size: number): Uint8Array;
  /** Write bytes to a native pointer. */
  writeBuffer(ptr: number, data: Uint8Array): void;
  /** Read a null-terminated string from a native pointer. */
  readCString(ptr: number): string;
  /** Register a transport callback set. Returns a cleanup function. */
  registerTransportCallbacks(
    send: (transportId: number, receiver: number, dataPtr: number, size: number) => number,
    receive: (transportId: number, sender: number, outDataPtr: number, outSizePtr: number) => number,
    receiveAll: (transportId: number, sendersPtr: number, senderCount: number, outDataPtr: number, outSizesPtr: number, outCountPtr: number) => number,
  ): () => void;
  /** Close the library. */
  close(): void;
}

// ---------------------------------------------------------------------------
// NativeBackend
// ---------------------------------------------------------------------------

export class NativeBackend implements CbMpcModule {
  readonly POINTER_SIZE: number;
  readonly CMEM_SIZE: number;
  readonly REF_SIZE: number;

  private transports: Map<number, DataTransport> = new Map();
  private cleanupCallbacks: (() => void) | null = null;

  constructor(private lib: NativeLib) {
    this.POINTER_SIZE = this.lib.fn("native_pointer_size")();
    this.CMEM_SIZE = this.lib.fn("native_cmem_size")();
    this.REF_SIZE = this.lib.fn("native_ref_size")();
    this.setupTransportCallbacks();
  }

  private setupTransportCallbacks(): void {
    this.cleanupCallbacks = this.lib.registerTransportCallbacks(
      // send
      (transportId, receiver, dataPtr, size) => {
        const transport = this.transports.get(transportId);
        if (!transport) return -1;
        const msg = this.lib.readBuffer(dataPtr, size);
        // For synchronous transport (e.g., SharedArrayBuffer-based mock)
        // we need the result synchronously. Cast to SyncDataTransport if available.
        const syncTransport = transport as unknown as SyncDataTransport;
        if (typeof syncTransport.sendSync === "function") {
          return syncTransport.sendSync(receiver, msg);
        }
        // Fallback: fire-and-forget (not ideal for real protocols)
        transport.send(receiver, msg);
        return 0;
      },
      // receive
      (transportId, sender, outDataPtr, outSizePtr) => {
        const transport = this.transports.get(transportId);
        if (!transport) return -1;
        const syncTransport = transport as unknown as SyncDataTransport;
        if (typeof syncTransport.receiveSync !== "function") {
          throw new Error("Native FFI requires synchronous transport (implement sendSync/receiveSync/receiveAllSync)");
        }
        const msg = syncTransport.receiveSync(sender);
        if (!msg) return -1;
        // Allocate memory for the message and write pointer/size to out params
        const msgPtr = this.lib.fn("wasm_alloc")(msg.length);
        this.lib.writeBuffer(msgPtr, msg);
        this.writePointerAt(outDataPtr, msgPtr);
        this.writeI32At(outSizePtr, msg.length);
        return 0;
      },
      // receiveAll
      (transportId, sendersPtr, senderCount, outDataPtr, outSizesPtr, outCountPtr) => {
        const transport = this.transports.get(transportId);
        if (!transport) return -1;
        const syncTransport = transport as unknown as SyncDataTransport;
        if (typeof syncTransport.receiveAllSync !== "function") {
          throw new Error("Native FFI requires synchronous transport");
        }
        // Read senders array
        const senders: number[] = [];
        for (let i = 0; i < senderCount; i++) {
          senders.push(this.getI32(sendersPtr + i * 4));
        }
        const messages = syncTransport.receiveAllSync(senders);
        if (!messages) return -1;

        // Flatten messages
        let totalSize = 0;
        for (const m of messages) totalSize += m.length;

        const dataPtr = this.lib.fn("wasm_alloc")(totalSize);
        const sizesPtr = this.lib.fn("wasm_alloc")(messages.length * 4);
        let offset = 0;
        for (let i = 0; i < messages.length; i++) {
          this.lib.writeBuffer(dataPtr + offset, messages[i]);
          this.writeI32At(sizesPtr + i * 4, messages[i].length);
          offset += messages[i].length;
        }

        this.writePointerAt(outDataPtr, dataPtr);
        this.writePointerAt(outSizesPtr, sizesPtr);
        this.writeI32At(outCountPtr, messages.length);
        return 0;
      },
    );
  }

  private writePointerAt(ptr: number, value: number): void {
    // For native, we need to write a pointer-sized value
    // We'll use the library's buffer write capability
    const buf = new Uint8Array(this.POINTER_SIZE);
    const view = new DataView(buf.buffer);
    if (this.POINTER_SIZE === 8) {
      view.setBigUint64(0, BigInt(value), true); // little-endian
    } else {
      view.setUint32(0, value, true);
    }
    this.lib.writeBuffer(ptr, buf);
  }

  private writeI32At(ptr: number, value: number): void {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setInt32(0, value, true);
    this.lib.writeBuffer(ptr, buf);
  }

  malloc(size: number): number {
    return this.lib.fn("wasm_alloc")(size);
  }

  free(ptr: number): void {
    this.lib.fn("wasm_free")(ptr);
  }

  writeBytes(data: Uint8Array): number {
    const ptr = this.malloc(data.length);
    this.lib.writeBuffer(ptr, data);
    return ptr;
  }

  readBytes(ptr: number, size: number): Uint8Array {
    return this.lib.readBuffer(ptr, size);
  }

  getI32(ptr: number): number {
    const buf = this.lib.readBuffer(ptr, 4);
    return new DataView(buf.buffer, buf.byteOffset).getInt32(0, true);
  }

  setI32(ptr: number, value: number): void {
    this.writeI32At(ptr, value);
  }

  getPointer(ptr: number): number {
    const buf = this.lib.readBuffer(ptr, this.POINTER_SIZE);
    const view = new DataView(buf.buffer, buf.byteOffset);
    if (this.POINTER_SIZE === 8) {
      return Number(view.getBigUint64(0, true));
    }
    return view.getUint32(0, true);
  }

  setPointer(ptr: number, value: number): void {
    this.writePointerAt(ptr, value);
  }

  readString(ptr: number): string {
    return this.lib.readCString(ptr);
  }

  allocString(str: string): number {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    const ptr = this.malloc(bytes.length + 1);
    this.lib.writeBuffer(ptr, bytes);
    // Write null terminator
    this.lib.writeBuffer(ptr + bytes.length, new Uint8Array([0]));
    return ptr;
  }

  writeCmem(data: Uint8Array): number {
    const dataPtr = this.writeBytes(data);
    const cmemPtr = this.lib.fn("wasm_new_cmem")(dataPtr, data.length);
    return cmemPtr;
  }

  readCmem(cmemPtr: number): Uint8Array {
    const dataPtr = this.lib.fn("wasm_cmem_data")(cmemPtr);
    const size = this.lib.fn("wasm_cmem_size")(cmemPtr);
    if (!dataPtr || size <= 0) return new Uint8Array(0);
    return this.readBytes(dataPtr, size);
  }

  freeCmem(cmemPtr: number): void {
    // Use wasm_free_cmem which frees both the data and the struct
    this.lib.fn("wasm_free_cmem")(cmemPtr);
  }

  allocRef(): number {
    return this.malloc(this.REF_SIZE);
  }

  readRef(refPtr: number): number {
    return this.getPointer(refPtr);
  }

  writeCmems(buffers: Uint8Array[]): number {
    const count = buffers.length;
    let totalSize = 0;
    for (const b of buffers) totalSize += b.length;

    const dataPtr = this.malloc(totalSize);
    const sizesPtr = this.malloc(count * 4);
    let offset = 0;
    for (let i = 0; i < count; i++) {
      this.lib.writeBuffer(dataPtr + offset, buffers[i]);
      this.setI32(sizesPtr + i * 4, buffers[i].length);
      offset += buffers[i].length;
    }

    // Use C-side accessor to avoid struct layout dependency
    // For now, manually construct: cmems_t = {int count, uint8_t* data, int* sizes}
    const cmemsSize = 4 + this.POINTER_SIZE * 2; // int + 2 pointers
    const cmemsPtr = this.malloc(cmemsSize);
    this.setI32(cmemsPtr, count);
    this.setPointer(cmemsPtr + this.POINTER_SIZE, dataPtr); // align after int+padding
    this.setPointer(cmemsPtr + this.POINTER_SIZE * 2, sizesPtr);
    return cmemsPtr;
  }

  readCmems(cmemsPtr: number): Uint8Array[] {
    const count = this.call("wasm_cmems_count", cmemsPtr);
    const result: Uint8Array[] = [];
    const elemCmem = this.malloc(this.CMEM_SIZE);
    for (let i = 0; i < count; i++) {
      this.call("wasm_cmems_get", cmemsPtr, i, elemCmem);
      const dataPtr = this.call("wasm_cmem_data", elemCmem);
      const size = this.call("wasm_cmem_size", elemCmem);
      if (dataPtr && size > 0) {
        result.push(this.readBytes(dataPtr, size));
      } else {
        result.push(new Uint8Array(0));
      }
    }
    this.free(elemCmem);
    return result;
  }

  freeCmems(cmemsPtr: number): void {
    // Read struct fields and free them
    const dataPtr = this.getPointer(cmemsPtr + this.POINTER_SIZE);
    const sizesPtr = this.getPointer(cmemsPtr + this.POINTER_SIZE * 2);
    if (dataPtr) this.free(dataPtr);
    if (sizesPtr) this.free(sizesPtr);
    this.free(cmemsPtr);
  }

  allocPartyNames(names: string[]): { arrayPtr: number; namePtrs: number[] } {
    const namePtrs = names.map((n) => this.allocString(n));
    const arrayPtr = this.malloc(namePtrs.length * this.POINTER_SIZE);
    for (let i = 0; i < namePtrs.length; i++) {
      this.setPointer(arrayPtr + i * this.POINTER_SIZE, namePtrs[i]);
    }
    return { arrayPtr, namePtrs };
  }

  pointToSec1(pointRefPtr: number): Uint8Array {
    const xCmem = this.malloc(this.CMEM_SIZE);
    const yCmem = this.malloc(this.CMEM_SIZE);
    this.call("wasm_ecc_point_get_x", pointRefPtr, xCmem);
    this.call("wasm_ecc_point_get_y", pointRefPtr, yCmem);
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
    return this.lib.fn(name)(...args);
  }

  async callAsync(name: string, ...args: number[]): Promise<number> {
    // Native calls are always synchronous (no ASYNCIFY).
    return this.call(name, ...args);
  }

  registerTransport(id: number, transport: DataTransport): void {
    this.transports.set(id, transport);
  }

  unregisterTransport(id: number): void {
    this.transports.delete(id);
  }

  seedRandom(entropy: Uint8Array): void {
    const ptr = this.writeBytes(entropy);
    const status = this.lib.fn("wasm_seed_random")(ptr, entropy.length);
    this.free(ptr);
    if (status !== 1) {
      console.warn("cb-mpc: OpenSSL PRNG seeding may have failed (RAND_status=" + status + ")");
    }
  }

  close(): void {
    if (this.cleanupCallbacks) {
      this.cleanupCallbacks();
      this.cleanupCallbacks = null;
    }
    this.lib.close();
  }
}

// ---------------------------------------------------------------------------
// Synchronous transport interface (required for native FFI)
// ---------------------------------------------------------------------------

/**
 * Synchronous transport for native FFI.
 * Native C code calls transport callbacks synchronously, so the JS-side
 * must provide synchronous send/receive.
 *
 * For concurrent multi-party protocols, use worker threads with
 * SharedArrayBuffer + Atomics for synchronous cross-thread messaging.
 */
export interface SyncDataTransport extends DataTransport {
  sendSync(receiver: number, message: Uint8Array): number;
  receiveSync(sender: number): Uint8Array;
  receiveAllSync(senders: number[]): Uint8Array[];
}

// ---------------------------------------------------------------------------
// Library path resolution
// ---------------------------------------------------------------------------

export function getLibraryPath(): string {
  const platform = process.platform === "darwin" ? "darwin" : "linux";
  const arch = process.arch === "arm64" ? "arm64" : "x64";
  const ext = platform === "darwin" ? "dylib" : "so";
  const dir = resolve(__dirname, "..", "..", "prebuilds", `${platform}-${arch}`);
  return join(dir, `libcbmpc.${ext}`);
}
