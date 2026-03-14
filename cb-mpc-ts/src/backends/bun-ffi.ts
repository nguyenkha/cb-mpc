/**
 * bun:ffi backend loader for cb-mpc.
 *
 * Uses Bun's built-in FFI to load the native shared library.
 * Only works in the Bun runtime.
 */

import type { NativeLib } from "./native.js";
import { NativeBackend, getLibraryPath } from "./native.js";

// All exported C functions and their signatures for bun:ffi
const FFI_SYMBOLS = {
  // Platform info
  native_pointer_size: { args: [] as const, returns: "i32" as const },
  native_cmem_size: { args: [] as const, returns: "i32" as const },
  native_ref_size: { args: [] as const, returns: "i32" as const },

  // Memory
  wasm_alloc: { args: ["i32"] as const, returns: "ptr" as const },
  wasm_free: { args: ["ptr"] as const, returns: "void" as const },
  wasm_new_cmem: { args: ["ptr", "i32"] as const, returns: "ptr" as const },
  wasm_free_cmem: { args: ["ptr"] as const, returns: "void" as const },
  wasm_cmem_data: { args: ["ptr"] as const, returns: "ptr" as const },
  wasm_cmem_size: { args: ["ptr"] as const, returns: "i32" as const },
  wasm_cmems_count: { args: ["ptr"] as const, returns: "i32" as const },
  wasm_cmems_get: { args: ["ptr", "i32", "ptr"] as const, returns: "i32" as const },

  // Entropy
  wasm_seed_random: { args: ["ptr", "i32"] as const, returns: "i32" as const },

  // Transport
  native_register_transport: { args: ["ptr", "ptr", "ptr"] as const, returns: "void" as const },

  // Curve
  wasm_new_ecurve: { args: ["i32", "ptr"] as const, returns: "void" as const },
  wasm_free_ecurve: { args: ["ptr"] as const, returns: "void" as const },
  ecurve_get_curve_code: { args: ["ptr"] as const, returns: "i32" as const },
  wasm_ecurve_generator: { args: ["ptr", "ptr"] as const, returns: "void" as const },
  wasm_ecurve_order: { args: ["ptr", "ptr"] as const, returns: "void" as const },
  wasm_ecurve_random_scalar: { args: ["ptr", "ptr"] as const, returns: "void" as const },
  wasm_ecurve_mul_generator: { args: ["ptr", "ptr", "i32", "ptr"] as const, returns: "void" as const },

  // Point
  wasm_free_ecc_point: { args: ["ptr"] as const, returns: "void" as const },
  wasm_ecc_point_from_bytes: { args: ["ptr", "i32", "ptr"] as const, returns: "void" as const },
  wasm_ecc_point_to_bytes: { args: ["ptr", "ptr"] as const, returns: "void" as const },
  wasm_ecc_point_multiply: { args: ["ptr", "ptr", "i32", "ptr"] as const, returns: "void" as const },
  wasm_ecc_point_add: { args: ["ptr", "ptr", "ptr"] as const, returns: "void" as const },
  wasm_ecc_point_subtract: { args: ["ptr", "ptr", "ptr"] as const, returns: "void" as const },
  wasm_ecc_point_get_x: { args: ["ptr", "ptr"] as const, returns: "void" as const },
  wasm_ecc_point_get_y: { args: ["ptr", "ptr"] as const, returns: "void" as const },
  ecc_point_is_zero: { args: ["ptr"] as const, returns: "i32" as const },
  ecc_point_equals: { args: ["ptr", "ptr"] as const, returns: "i32" as const },

  // Scalar
  wasm_bn_add: { args: ["ptr", "i32", "ptr", "i32", "ptr"] as const, returns: "void" as const },
  wasm_ec_mod_add: { args: ["ptr", "ptr", "i32", "ptr", "i32", "ptr"] as const, returns: "void" as const },
  wasm_bn_from_int64: { args: ["i64", "ptr"] as const, returns: "void" as const },

  // Verification
  wasm_ecc_verify_der: { args: ["i32", "ptr", "i32", "ptr", "i32", "ptr", "i32"] as const, returns: "i32" as const },

  // Job creation
  wasm_new_job_2p: { args: ["i32", "i32", "ptr", "ptr"] as const, returns: "ptr" as const },
  wasm_new_job_mp: { args: ["i32", "i32", "i32", "ptr", "i32"] as const, returns: "ptr" as const },
  free_job_2p: { args: ["ptr"] as const, returns: "void" as const },
  free_job_mp: { args: ["ptr"] as const, returns: "void" as const },
  is_peer1: { args: ["ptr"] as const, returns: "i32" as const },
  is_peer2: { args: ["ptr"] as const, returns: "i32" as const },
  get_role_index: { args: ["ptr"] as const, returns: "i32" as const },
  get_party_idx: { args: ["ptr"] as const, returns: "i32" as const },
  get_n_parties: { args: ["ptr"] as const, returns: "i32" as const },

  // ECDSA 2P
  mpc_ecdsa2p_dkg: { args: ["ptr", "i32", "ptr"] as const, returns: "i32" as const },
  mpc_ecdsa2p_refresh: { args: ["ptr", "ptr", "ptr"] as const, returns: "i32" as const },
  mpc_ecdsa2p_sign: { args: ["ptr", "ptr", "ptr", "i32", "ptr", "i32", "ptr"] as const, returns: "i32" as const },
  wasm_free_mpc_ecdsa2p_key: { args: ["ptr"] as const, returns: "void" as const },
  mpc_ecdsa2p_key_get_role_index: { args: ["ptr"] as const, returns: "i32" as const },
  mpc_ecdsa2p_key_get_curve_code: { args: ["ptr"] as const, returns: "i32" as const },
  wasm_mpc_ecdsa2p_key_get_Q: { args: ["ptr", "ptr"] as const, returns: "void" as const },
  wasm_mpc_ecdsa2p_key_get_x_share: { args: ["ptr", "ptr"] as const, returns: "void" as const },

  // EC Key MP
  mpc_eckey_mp_dkg: { args: ["ptr", "ptr", "ptr"] as const, returns: "i32" as const },
  mpc_eckey_mp_refresh: { args: ["ptr", "ptr", "ptr", "i32", "ptr"] as const, returns: "i32" as const },
  wasm_free_mpc_eckey_mp: { args: ["ptr"] as const, returns: "void" as const },
  wasm_mpc_eckey_mp_get_Q: { args: ["ptr", "ptr"] as const, returns: "void" as const },
  mpc_eckey_mp_get_curve: { args: ["ptr"] as const, returns: "ptr" as const },
  mpc_eckey_mp_get_x_share: { args: ["ptr", "ptr"] as const, returns: "void" as const },
  mpc_eckey_mp_get_party_name: { args: ["ptr"] as const, returns: "ptr" as const },
  serialize_mpc_eckey_mp: { args: ["ptr", "ptr"] as const, returns: "i32" as const },
  deserialize_mpc_eckey_mp: { args: ["ptr", "i32", "ptr"] as const, returns: "i32" as const },

  // ECDSA MP
  mpc_ecdsampc_sign: { args: ["ptr", "ptr", "ptr", "i32", "i32", "ptr"] as const, returns: "i32" as const },

  // EdDSA MP
  mpc_eddsampc_sign: { args: ["ptr", "ptr", "ptr", "i32", "i32", "ptr"] as const, returns: "i32" as const },

  // EC Key 2P / Schnorr 2P
  mpc_eckey_2p_dkg: { args: ["ptr", "i32", "ptr"] as const, returns: "i32" as const },
  wasm_free_mpc_eckey_2p: { args: ["ptr"] as const, returns: "void" as const },
  mpc_eckey_2p_get_role_index: { args: ["ptr"] as const, returns: "i32" as const },
  mpc_eckey_2p_get_curve_code: { args: ["ptr"] as const, returns: "i32" as const },
  wasm_mpc_eckey_2p_get_Q: { args: ["ptr", "ptr"] as const, returns: "void" as const },
  wasm_mpc_eckey_2p_get_x_share: { args: ["ptr", "ptr"] as const, returns: "void" as const },
  wasm_mpc_schnorr2p_eddsa_sign: { args: ["ptr", "ptr", "ptr", "i32", "ptr"] as const, returns: "i32" as const },
} as const;

class BunFfiLib implements NativeLib {
  private symbols: Record<string, (...args: any[]) => any>;
  private callbacks: any[] = [];

  constructor(libPath: string) {
    // @ts-ignore - bun:ffi is Bun-only
    const { dlopen, ptr: bunPtr, toArrayBuffer, CString, JSCallback } = require("bun:ffi");
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
