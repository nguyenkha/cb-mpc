// Binding layer for cb-mpc.
//
// This file bridges the C API (from cgobinding/) to JavaScript runtimes.
// It supports two build modes:
//   1. WASM (Emscripten): uses ASYNCIFY for async JS transport callbacks
//   2. Native shared library (.dylib/.so): loaded via FFI (koffi)
//
// The native build uses function-pointer registration instead of EM_ASYNC_JS.

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define EXPORT EXPORT
#else
#define EXPORT __attribute__((visibility("default")))
#endif

#include <openssl/rand.h>

#include <cstdlib>
#include <cstring>

#include <cbmpc/core/cmem.h>

// ---------------------------------------------------------------------------
// Entropy seeding
// ---------------------------------------------------------------------------

#ifdef __EMSCRIPTEN__
// Emscripten may not provide getentropy() when FILESYSTEM=0. We implement it
// by calling into JavaScript's crypto.getRandomValues().

EM_JS(int, js_get_random_values, (uint8_t* buf, int size), {
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(Module.HEAPU8.subarray(buf, buf + size));
    return 0;
  }
  return -1;
});

extern "C" {
int getentropy(void* buffer, size_t length) {
  if (length > 256) {
    return -1;
  }
  return js_get_random_values(static_cast<uint8_t*>(buffer), static_cast<int>(length));
}
}
#endif // __EMSCRIPTEN__

// Pull in the CGO C headers so their symbols are linked.
#include "ac.h"
#include "agree_random.h"
#include "curve.h"
#include "ecdsa2p.h"
#include "ecdsamp.h"
#include "eckeymp.h"
#include "eddsamp.h"
#include "network.h"
#include "pve.h"
#include "schnorr2p.h"
#include "zk.h"

// ---------------------------------------------------------------------------
// Transport callbacks
// ---------------------------------------------------------------------------

#ifdef __EMSCRIPTEN__
// WASM: JS-side transport callbacks invoked via ASYNCIFY

EM_ASYNC_JS(int, js_transport_send, (int transport_id, int receiver, const uint8_t* data, int size), {
  const cb = Module._transportCallbacks ? Module._transportCallbacks[transport_id] : null;
  if (!cb || !cb.send) {
    console.error('js_transport_send: no callback for transport_id=' + transport_id +
      ', keys=' + (Module._transportCallbacks ? Object.keys(Module._transportCallbacks) : 'none'));
    return -1;
  }
  const msg = Module.HEAPU8.slice(data, data + size);
  return await cb.send(receiver, msg);
});

EM_ASYNC_JS(int, js_transport_receive, (int transport_id, int sender, uint8_t** out_data, int* out_size), {
  const cb = Module._transportCallbacks[transport_id];
  if (!cb || !cb.receive) return -1;
  const msg = await cb.receive(sender);
  if (!msg || !(msg instanceof Uint8Array)) return -1;
  const ptr = Module._malloc(msg.length);
  Module.HEAPU8.set(msg, ptr);
  Module.setValue(out_data, ptr, '*');
  Module.setValue(out_size, msg.length, 'i32');
  return 0;
});

EM_ASYNC_JS(int, js_transport_receive_all,
            (int transport_id, const int* senders, int sender_count,
             uint8_t** out_data, int** out_sizes, int* out_count), {
  const cb = Module._transportCallbacks[transport_id];
  if (!cb || !cb.receiveAll) return -1;
  const senderArr = [];
  for (let i = 0; i < sender_count; i++) {
    senderArr.push(Module.getValue(senders + i * 4, 'i32'));
  }
  const messages = await cb.receiveAll(senderArr);
  if (!messages || !Array.isArray(messages)) return -1;

  let totalSize = 0;
  for (const m of messages) totalSize += m.length;

  const dataPtr = Module._malloc(totalSize);
  const sizesPtr = Module._malloc(messages.length * 4);
  let offset = 0;
  for (let i = 0; i < messages.length; i++) {
    Module.HEAPU8.set(messages[i], dataPtr + offset);
    Module.setValue(sizesPtr + i * 4, messages[i].length, 'i32');
    offset += messages[i].length;
  }

  Module.setValue(out_data, dataPtr, '*');
  Module.setValue(out_sizes, sizesPtr, '*');
  Module.setValue(out_count, messages.length, 'i32');
  return 0;
});

static int send_trampoline(void* ctx, int receiver, cmem_t message) {
  int transport_id = static_cast<int>(reinterpret_cast<intptr_t>(ctx));
  return js_transport_send(transport_id, receiver, message.data, message.size);
}

static int receive_trampoline(void* ctx, int sender, cmem_t* message) {
  int transport_id = static_cast<int>(reinterpret_cast<intptr_t>(ctx));
  uint8_t* data = nullptr;
  int size = 0;
  int rc = js_transport_receive(transport_id, sender, &data, &size);
  if (rc != 0) return rc;
  message->data = data;
  message->size = size;
  return 0;
}

static int receive_all_trampoline(void* ctx, int* senders, int sender_count, cmems_t* messages) {
  int transport_id = static_cast<int>(reinterpret_cast<intptr_t>(ctx));
  uint8_t* data = nullptr;
  int* sizes = nullptr;
  int count = 0;
  int rc = js_transport_receive_all(transport_id, senders, sender_count, &data, &sizes, &count);
  if (rc != 0) return rc;
  messages->data = data;
  messages->sizes = sizes;
  messages->count = count;
  return 0;
}

static const data_transport_callbacks_t wasm_callbacks = {
    send_trampoline,
    receive_trampoline,
    receive_all_trampoline,
};

#else
// Native: transport callbacks are registered via function pointers from JS FFI.
// The FFI layer registers send/receive/receiveAll function pointers per transport_id.

// Function pointer types matching the transport callback signatures.
typedef int (*native_send_fn)(int transport_id, int receiver, const uint8_t* data, int size);
typedef int (*native_receive_fn)(int transport_id, int sender, uint8_t** out_data, int* out_size);
typedef int (*native_receive_all_fn)(int transport_id, const int* senders, int sender_count,
                                      uint8_t** out_data, int** out_sizes, int* out_count);

// Global function pointers set by JS before protocol calls.
static native_send_fn g_native_send = nullptr;
static native_receive_fn g_native_receive = nullptr;
static native_receive_all_fn g_native_receive_all = nullptr;

static int native_send_trampoline(void* ctx, int receiver, cmem_t message) {
  if (!g_native_send) return -1;
  int transport_id = static_cast<int>(reinterpret_cast<intptr_t>(ctx));
  return g_native_send(transport_id, receiver, message.data, message.size);
}

static int native_receive_trampoline(void* ctx, int sender, cmem_t* message) {
  if (!g_native_receive) return -1;
  int transport_id = static_cast<int>(reinterpret_cast<intptr_t>(ctx));
  uint8_t* data = nullptr;
  int size = 0;
  int rc = g_native_receive(transport_id, sender, &data, &size);
  if (rc != 0) return rc;
  message->data = data;
  message->size = size;
  return 0;
}

static int native_receive_all_trampoline(void* ctx, int* senders, int sender_count, cmems_t* messages) {
  if (!g_native_receive_all) return -1;
  int transport_id = static_cast<int>(reinterpret_cast<intptr_t>(ctx));
  uint8_t* data = nullptr;
  int* sizes = nullptr;
  int count = 0;
  int rc = g_native_receive_all(transport_id, senders, sender_count, &data, &sizes, &count);
  if (rc != 0) return rc;
  messages->data = data;
  messages->sizes = sizes;
  messages->count = count;
  return 0;
}

static const data_transport_callbacks_t native_callbacks = {
    native_send_trampoline,
    native_receive_trampoline,
    native_receive_all_trampoline,
};
#endif // __EMSCRIPTEN__

// ---------------------------------------------------------------------------
// WASM-exported helpers
// ---------------------------------------------------------------------------

extern "C" {

// -- Platform info (struct sizes for FFI) --

EXPORT
int native_pointer_size() { return static_cast<int>(sizeof(void*)); }

EXPORT
int native_cmem_size() { return static_cast<int>(sizeof(cmem_t)); }

EXPORT
int native_ref_size() { return static_cast<int>(sizeof(ecurve_ref)); }

// -- cmem_t write helper (for FFI: allocate and populate a cmem_t) --

EXPORT
cmem_t* wasm_new_cmem(uint8_t* data, int size) {
  cmem_t* cmem = static_cast<cmem_t*>(malloc(sizeof(cmem_t)));
  cmem->data = data;
  cmem->size = size;
  return cmem;
}

EXPORT
void wasm_free_cmem(cmem_t* cmem) {
  if (cmem) {
    if (cmem->data) free(cmem->data);
    free(cmem);
  }
}

// -- Entropy seeding --

EXPORT
int wasm_seed_random(const uint8_t* data, int size) {
  RAND_seed(data, size);
  return RAND_status();
}

// -- Memory allocation helpers for JS interop --

EXPORT
uint8_t* wasm_alloc(int size) {
  return static_cast<uint8_t*>(malloc(size));
}

EXPORT
void wasm_free(void* ptr) {
  free(ptr);
}

// -- cmem_t accessors (JS can't dereference structs directly) --

EXPORT
uint8_t* wasm_cmem_data(cmem_t* cmem) {
  return cmem ? cmem->data : nullptr;
}

EXPORT
int wasm_cmem_size(cmem_t* cmem) {
  return cmem ? cmem->size : 0;
}

EXPORT
int wasm_cmems_count(cmems_t* cmems) {
  return cmems ? cmems->count : 0;
}

// Extract the i-th element from a cmems_t into a cmem_t (written to out).
EXPORT
int wasm_cmems_get(cmems_t* cmems, int index, cmem_t* out) {
  if (!cmems || !out || index < 0 || index >= cmems->count) return -1;
  const uint8_t* p = cmems->data;
  for (int i = 0; i < index; i++) {
    p += cmems->sizes[i];
  }
  out->data = const_cast<uint8_t*>(p);
  out->size = cmems->sizes[index];
  return 0;
}

// -- Transport callback registration (native only) --

#ifndef __EMSCRIPTEN__
EXPORT
void native_register_transport(native_send_fn send_fn, native_receive_fn recv_fn, native_receive_all_fn recv_all_fn) {
  g_native_send = send_fn;
  g_native_receive = recv_fn;
  g_native_receive_all = recv_all_fn;
}
#endif

// -- Job creation wrappers --

EXPORT
job_2p_ref* wasm_new_job_2p(int transport_id, int party_index,
                            const char* pname0, const char* pname1) {
  const char* pnames[2] = {pname0, pname1};
  void* ctx = reinterpret_cast<void*>(static_cast<intptr_t>(transport_id));
#ifdef __EMSCRIPTEN__
  return new_job_2p(&wasm_callbacks, ctx, party_index, pnames, 2);
#else
  return new_job_2p(&native_callbacks, ctx, party_index, pnames, 2);
#endif
}

EXPORT
job_mp_ref* wasm_new_job_mp(int transport_id, int party_count, int party_index,
                            const char** pnames, int pname_count) {
  void* ctx = reinterpret_cast<void*>(static_cast<intptr_t>(transport_id));
#ifdef __EMSCRIPTEN__
  return new_job_mp(&wasm_callbacks, ctx, party_count, party_index, pnames, pname_count);
#else
  return new_job_mp(&native_callbacks, ctx, party_count, party_index, pnames, pname_count);
#endif
}

// ---------------------------------------------------------------------------
// Struct-return wrappers.
//
// WASM's ABI returns structs via a hidden sret pointer that ccall/cwrap
// cannot handle.  These thin wrappers write the result to a caller-provided
// output pointer instead, giving JS a simple scalar-only interface.
// ---------------------------------------------------------------------------

// -- Free wrappers (original funcs take structs by value) --

EXPORT
void wasm_free_ecurve(ecurve_ref* ref) {
  free_ecurve(*ref);
}

EXPORT
void wasm_free_ecc_point(ecc_point_ref* ref) {
  free_ecc_point(*ref);
}

EXPORT
void wasm_free_mpc_ecdsa2p_key(mpc_ecdsa2pc_key_ref* ref) {
  free_mpc_ecdsa2p_key(*ref);
}

EXPORT
void wasm_free_mpc_eckey_mp(mpc_eckey_mp_ref* ref) {
  free_mpc_eckey_mp(*ref);
}

// -- Curve wrappers --

EXPORT
void wasm_new_ecurve(int curve_code, ecurve_ref* out) {
  *out = new_ecurve(curve_code);
}

EXPORT
void wasm_ecurve_generator(ecurve_ref* curve, ecc_point_ref* out) {
  *out = ecurve_generator(curve);
}

EXPORT
void wasm_ecurve_order(ecurve_ref* curve, cmem_t* out) {
  *out = ecurve_order(curve);
}

EXPORT
void wasm_ecurve_random_scalar(ecurve_ref* curve, cmem_t* out) {
  *out = ecurve_random_scalar(curve);
}

EXPORT
void wasm_ecurve_mul_generator(ecurve_ref* curve, uint8_t* s_data, int s_size, ecc_point_ref* out) {
  cmem_t scalar = {s_data, s_size};
  *out = ecurve_mul_generator(curve, scalar);
}

// -- Point wrappers --

EXPORT
void wasm_ecc_point_from_bytes(uint8_t* data, int size, ecc_point_ref* out) {
  cmem_t point_bytes = {data, size};
  *out = ecc_point_from_bytes(point_bytes);
}

EXPORT
void wasm_ecc_point_to_bytes(ecc_point_ref* point, cmem_t* out) {
  *out = ecc_point_to_bytes(point);
}

EXPORT
void wasm_ecc_point_multiply(ecc_point_ref* point, uint8_t* s_data, int s_size, ecc_point_ref* out) {
  cmem_t scalar = {s_data, s_size};
  *out = ecc_point_multiply(point, scalar);
}

EXPORT
void wasm_ecc_point_add(ecc_point_ref* p1, ecc_point_ref* p2, ecc_point_ref* out) {
  *out = ecc_point_add(p1, p2);
}

EXPORT
void wasm_ecc_point_subtract(ecc_point_ref* p1, ecc_point_ref* p2, ecc_point_ref* out) {
  *out = ecc_point_subtract(p1, p2);
}

EXPORT
void wasm_ecc_point_get_x(ecc_point_ref* point, cmem_t* out) {
  *out = ecc_point_get_x(point);
}

EXPORT
void wasm_ecc_point_get_y(ecc_point_ref* point, cmem_t* out) {
  *out = ecc_point_get_y(point);
}

// -- Scalar wrappers --

EXPORT
void wasm_bn_add(uint8_t* a_data, int a_size, uint8_t* b_data, int b_size, cmem_t* out) {
  cmem_t a = {a_data, a_size};
  cmem_t b = {b_data, b_size};
  *out = bn_add(a, b);
}

EXPORT
void wasm_ec_mod_add(ecurve_ref* curve, uint8_t* a_data, int a_size, uint8_t* b_data, int b_size, cmem_t* out) {
  cmem_t a = {a_data, a_size};
  cmem_t b = {b_data, b_size};
  *out = ec_mod_add(curve, a, b);
}

EXPORT
void wasm_bn_from_int64(int64_t value, cmem_t* out) {
  *out = bn_from_int64(value);
}

// -- ECDSA 2P wrappers --

EXPORT
void wasm_mpc_ecdsa2p_key_get_Q(mpc_ecdsa2pc_key_ref* key, ecc_point_ref* out) {
  *out = mpc_ecdsa2p_key_get_Q(key);
}

EXPORT
void wasm_mpc_ecdsa2p_key_get_x_share(mpc_ecdsa2pc_key_ref* key, cmem_t* out) {
  *out = mpc_ecdsa2p_key_get_x_share(key);
}

// -- Verification wrapper --

EXPORT
int wasm_ecc_verify_der(int curve_code,
                        uint8_t* pub_data, int pub_size,
                        uint8_t* hash_data, int hash_size,
                        uint8_t* sig_data, int sig_size) {
  cmem_t pub_oct = {pub_data, pub_size};
  cmem_t hash = {hash_data, hash_size};
  cmem_t der_sig = {sig_data, sig_size};
  return ecc_verify_der(curve_code, pub_oct, hash, der_sig);
}

// -- EC Key MP wrappers --

EXPORT
void wasm_mpc_eckey_mp_get_Q(mpc_eckey_mp_ref* key, ecc_point_ref* out) {
  *out = mpc_eckey_mp_get_Q(key);
}

// -- EC Key 2P / Schnorr 2P wrappers --

EXPORT
void wasm_free_mpc_eckey_2p(mpc_eckey_2p_ref* ref) {
  free_mpc_eckey_2p(*ref);
}

EXPORT
void wasm_mpc_eckey_2p_get_Q(mpc_eckey_2p_ref* key, ecc_point_ref* out) {
  *out = mpc_eckey_2p_get_Q(key);
}

EXPORT
void wasm_mpc_eckey_2p_get_x_share(mpc_eckey_2p_ref* key, cmem_t* out) {
  *out = mpc_eckey_2p_get_x_share(key);
}

EXPORT
int wasm_mpc_schnorr2p_eddsa_sign(job_2p_ref* job, mpc_eckey_2p_ref* key,
                                   uint8_t* msg_data, int msg_size,
                                   cmem_t* sig_out) {
  cmem_t msg = {msg_data, msg_size};
  return mpc_schnorr2p_eddsa_sign(job, key, msg, sig_out);
}

}  // extern "C"
