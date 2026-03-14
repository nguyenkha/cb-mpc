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

class KoffiLib implements NativeLib {
  private lib: any;
  private koffi: any;
  private fnCache: Map<string, (...args: any[]) => any> = new Map();
  private registeredCallbacks: any[] = [];

  // Function signatures for all exported C functions
  private static readonly SIGNATURES: Record<string, string> = {
    // Platform info
    native_pointer_size: "int native_pointer_size()",
    native_cmem_size: "int native_cmem_size()",
    native_ref_size: "int native_ref_size()",

    // Memory
    wasm_alloc: "void* wasm_alloc(int size)",
    wasm_free: "void wasm_free(void* ptr)",
    wasm_new_cmem: "void* wasm_new_cmem(void* data, int size)",
    wasm_free_cmem: "void wasm_free_cmem(void* cmem)",
    wasm_cmem_data: "void* wasm_cmem_data(void* cmem)",
    wasm_cmem_size: "int wasm_cmem_size(void* cmem)",
    wasm_cmems_count: "int wasm_cmems_count(void* cmems)",
    wasm_cmems_get: "int wasm_cmems_get(void* cmems, int index, void* out)",

    // Entropy
    wasm_seed_random: "int wasm_seed_random(const void* data, int size)",

    // Transport
    native_register_transport: "void native_register_transport(void* send_fn, void* recv_fn, void* recv_all_fn)",

    // Curve
    wasm_new_ecurve: "void wasm_new_ecurve(int curve_code, void* out)",
    wasm_free_ecurve: "void wasm_free_ecurve(void* ref)",
    ecurve_get_curve_code: "int ecurve_get_curve_code(void* curve)",
    wasm_ecurve_generator: "void wasm_ecurve_generator(void* curve, void* out)",
    wasm_ecurve_order: "void wasm_ecurve_order(void* curve, void* out)",
    wasm_ecurve_random_scalar: "void wasm_ecurve_random_scalar(void* curve, void* out)",
    wasm_ecurve_mul_generator: "void wasm_ecurve_mul_generator(void* curve, void* s_data, int s_size, void* out)",

    // Point
    wasm_free_ecc_point: "void wasm_free_ecc_point(void* ref)",
    wasm_ecc_point_from_bytes: "void wasm_ecc_point_from_bytes(void* data, int size, void* out)",
    wasm_ecc_point_to_bytes: "void wasm_ecc_point_to_bytes(void* point, void* out)",
    wasm_ecc_point_multiply: "void wasm_ecc_point_multiply(void* point, void* s_data, int s_size, void* out)",
    wasm_ecc_point_add: "void wasm_ecc_point_add(void* p1, void* p2, void* out)",
    wasm_ecc_point_subtract: "void wasm_ecc_point_subtract(void* p1, void* p2, void* out)",
    wasm_ecc_point_get_x: "void wasm_ecc_point_get_x(void* point, void* out)",
    wasm_ecc_point_get_y: "void wasm_ecc_point_get_y(void* point, void* out)",
    ecc_point_is_zero: "int ecc_point_is_zero(void* point)",
    ecc_point_equals: "int ecc_point_equals(void* p1, void* p2)",

    // Scalar
    wasm_bn_add: "void wasm_bn_add(void* a_data, int a_size, void* b_data, int b_size, void* out)",
    wasm_ec_mod_add: "void wasm_ec_mod_add(void* curve, void* a_data, int a_size, void* b_data, int b_size, void* out)",
    wasm_bn_from_int64: "void wasm_bn_from_int64(int64_t value, void* out)",

    // Verification
    wasm_ecc_verify_der: "int wasm_ecc_verify_der(int curve_code, void* pub_data, int pub_size, void* hash_data, int hash_size, void* sig_data, int sig_size)",

    // Job creation
    wasm_new_job_2p: "void* wasm_new_job_2p(int transport_id, int party_index, const char* pname0, const char* pname1)",
    wasm_new_job_mp: "void* wasm_new_job_mp(int transport_id, int party_count, int party_index, void* pnames, int pname_count)",
    free_job_2p: "void free_job_2p(void* job)",
    free_job_mp: "void free_job_mp(void* job)",
    is_peer1: "int is_peer1(void* job)",
    is_peer2: "int is_peer2(void* job)",
    get_role_index: "int get_role_index(void* job)",
    get_party_idx: "int get_party_idx(void* job)",
    get_n_parties: "int get_n_parties(void* job)",

    // ECDSA 2P
    mpc_ecdsa2p_dkg: "int mpc_ecdsa2p_dkg(void* job, int curve_code, void* key_out)",
    mpc_ecdsa2p_refresh: "int mpc_ecdsa2p_refresh(void* job, void* key_in, void* key_out)",
    mpc_ecdsa2p_sign: "int mpc_ecdsa2p_sign(void* job, void* key, void* session_id, int session_id_size, void* msg_hash, int msg_hash_size, void* sig_out)",
    wasm_free_mpc_ecdsa2p_key: "void wasm_free_mpc_ecdsa2p_key(void* ref)",
    mpc_ecdsa2p_key_get_role_index: "int mpc_ecdsa2p_key_get_role_index(void* key)",
    mpc_ecdsa2p_key_get_curve_code: "int mpc_ecdsa2p_key_get_curve_code(void* key)",
    wasm_mpc_ecdsa2p_key_get_Q: "void wasm_mpc_ecdsa2p_key_get_Q(void* key, void* out)",
    wasm_mpc_ecdsa2p_key_get_x_share: "void wasm_mpc_ecdsa2p_key_get_x_share(void* key, void* out)",

    // EC Key MP
    mpc_eckey_mp_dkg: "int mpc_eckey_mp_dkg(void* job, void* curve, void* key_out)",
    mpc_eckey_mp_refresh: "int mpc_eckey_mp_refresh(void* job, void* key_in, void* session_id, int session_id_size, void* key_out)",
    wasm_free_mpc_eckey_mp: "void wasm_free_mpc_eckey_mp(void* ref)",
    wasm_mpc_eckey_mp_get_Q: "void wasm_mpc_eckey_mp_get_Q(void* key, void* out)",
    mpc_eckey_mp_get_curve: "void* mpc_eckey_mp_get_curve(void* key)",
    mpc_eckey_mp_get_x_share: "void wasm_mpc_eckey_mp_get_x_share(void* key, void* out)",
    mpc_eckey_mp_get_party_name: "const char* mpc_eckey_mp_get_party_name(void* key)",
    serialize_mpc_eckey_mp: "int serialize_mpc_eckey_mp(void* key, void* cmems_out)",
    deserialize_mpc_eckey_mp: "int deserialize_mpc_eckey_mp(void* parts, int parts_count, void* key_out)",

    // ECDSA MP
    mpc_ecdsampc_sign: "int mpc_ecdsampc_sign(void* job, void* key, void* msg_hash, int msg_hash_size, int sig_receiver, void* sig_out)",

    // EdDSA MP
    mpc_eddsampc_sign: "int mpc_eddsampc_sign(void* job, void* key, void* msg, int msg_size, int sig_receiver, void* sig_out)",

    // EC Key 2P / Schnorr 2P
    mpc_eckey_2p_dkg: "int mpc_eckey_2p_dkg(void* job, int curve_code, void* key_out)",
    wasm_free_mpc_eckey_2p: "void wasm_free_mpc_eckey_2p(void* ref)",
    mpc_eckey_2p_get_role_index: "int mpc_eckey_2p_get_role_index(void* key)",
    mpc_eckey_2p_get_curve_code: "int mpc_eckey_2p_get_curve_code(void* key)",
    wasm_mpc_eckey_2p_get_Q: "void wasm_mpc_eckey_2p_get_Q(void* key, void* out)",
    wasm_mpc_eckey_2p_get_x_share: "void wasm_mpc_eckey_2p_get_x_share(void* key, void* out)",
    wasm_mpc_schnorr2p_eddsa_sign: "int wasm_mpc_schnorr2p_eddsa_sign(void* job, void* key, void* msg_data, int msg_size, void* sig_out)",
  };

  constructor(libPath: string) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    this.koffi = require("koffi");
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
    // koffi.decode can read raw bytes from a pointer
    const buf = Buffer.alloc(size);
    koffi.decode(ptr, koffi.types.uint8, size, buf);
    return new Uint8Array(buf);
  }

  writeBuffer(ptr: number, data: Uint8Array): void {
    if (!ptr || data.length === 0) return;
    const koffi = this.koffi;
    // koffi.encode writes bytes to a pointer
    koffi.encode(ptr, koffi.types.uint8, Array.from(data));
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
    const sendType = koffi.proto("int native_send_cb(int, int, const uint8_t*, int)");
    const recvType = koffi.proto("int native_recv_cb(int, int, uint8_t**, int*)");
    const recvAllType = koffi.proto("int native_recv_all_cb(int, const int*, int, uint8_t**, int**, int*)");

    // Register callbacks
    const sendCb = koffi.register(send, koffi.pointer(sendType));
    const recvCb = koffi.register(receive, koffi.pointer(recvType));
    const recvAllCb = koffi.register(receiveAll, koffi.pointer(recvAllType));

    this.registeredCallbacks.push(sendCb, recvCb, recvAllCb);
    this.fn("native_register_transport")(sendCb, recvCb, recvAllCb);

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
  const lib = new KoffiLib(path);
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
