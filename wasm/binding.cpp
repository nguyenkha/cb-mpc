// WASM binding layer for cb-mpc.
//
// This file bridges the C API (from cgobinding/) to Emscripten/WASM,
// providing memory helpers and a callback-based data transport that
// delegates to JavaScript send/receive functions via ASYNCIFY.

#include <emscripten.h>
#include <openssl/rand.h>

#include <cstdlib>
#include <cstring>

#include <cbmpc/core/cmem.h>

// ---------------------------------------------------------------------------
// Provide getentropy() for OpenSSL's DRBG seeding in WASM.
//
// Emscripten may not provide getentropy() when FILESYSTEM=0. We implement it
// by calling into JavaScript's crypto.getRandomValues(), which is available
// in all modern browsers and Node.js.
// ---------------------------------------------------------------------------

EM_JS(int, js_get_random_values, (uint8_t* buf, int size), {
  // Use globalThis.crypto which works in both browsers and Node.js 19+
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(Module.HEAPU8.subarray(buf, buf + size));
    return 0;
  }
  return -1;
});

extern "C" {
int getentropy(void* buffer, size_t length) {
  if (length > 256) {
    // POSIX getentropy() limit
    return -1;
  }
  return js_get_random_values(static_cast<uint8_t*>(buffer), static_cast<int>(length));
}
}

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
#include "zk.h"

// ---------------------------------------------------------------------------
// JS-side transport callbacks (implemented in JavaScript, called via ASYNCIFY)
// ---------------------------------------------------------------------------

// These are defined in JavaScript and invoked synchronously from C++ thanks to
// Emscripten ASYNCIFY.  The JS implementations can be async (e.g. fetching
// from a WebSocket) and ASYNCIFY will transparently pause/resume the WASM stack.

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

  // Flatten messages into a single buffer with size array
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

// ---------------------------------------------------------------------------
// C callback trampolines for data_transport_callbacks_t
// ---------------------------------------------------------------------------

// The void* go_impl_ptr carries the transport_id (cast to intptr_t).

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

// ---------------------------------------------------------------------------
// WASM-exported helpers
// ---------------------------------------------------------------------------

extern "C" {

// -- Entropy seeding (WASM has no native entropy source) --

EMSCRIPTEN_KEEPALIVE
int wasm_seed_random(const uint8_t* data, int size) {
  RAND_seed(data, size);
  return RAND_status();
}

// -- Memory allocation helpers for JS interop --

EMSCRIPTEN_KEEPALIVE
uint8_t* wasm_alloc(int size) {
  return static_cast<uint8_t*>(malloc(size));
}

EMSCRIPTEN_KEEPALIVE
void wasm_free(void* ptr) {
  free(ptr);
}

// -- cmem_t accessors (JS can't dereference structs directly) --

EMSCRIPTEN_KEEPALIVE
uint8_t* wasm_cmem_data(cmem_t* cmem) {
  return cmem ? cmem->data : nullptr;
}

EMSCRIPTEN_KEEPALIVE
int wasm_cmem_size(cmem_t* cmem) {
  return cmem ? cmem->size : 0;
}

EMSCRIPTEN_KEEPALIVE
int wasm_cmems_count(cmems_t* cmems) {
  return cmems ? cmems->count : 0;
}

// Extract the i-th element from a cmems_t into a cmem_t (written to out).
EMSCRIPTEN_KEEPALIVE
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

// -- Job creation wrappers (using wasm transport callbacks) --

EMSCRIPTEN_KEEPALIVE
job_2p_ref* wasm_new_job_2p(int transport_id, int party_index,
                            const char* pname0, const char* pname1) {
  const char* pnames[2] = {pname0, pname1};
  void* ctx = reinterpret_cast<void*>(static_cast<intptr_t>(transport_id));
  return new_job_2p(&wasm_callbacks, ctx, party_index, pnames, 2);
}

EMSCRIPTEN_KEEPALIVE
job_mp_ref* wasm_new_job_mp(int transport_id, int party_count, int party_index,
                            const char** pnames, int pname_count) {
  void* ctx = reinterpret_cast<void*>(static_cast<intptr_t>(transport_id));
  return new_job_mp(&wasm_callbacks, ctx, party_count, party_index, pnames, pname_count);
}

// ---------------------------------------------------------------------------
// Struct-return wrappers.
//
// WASM's ABI returns structs via a hidden sret pointer that ccall/cwrap
// cannot handle.  These thin wrappers write the result to a caller-provided
// output pointer instead, giving JS a simple scalar-only interface.
// ---------------------------------------------------------------------------

// -- Free wrappers (original funcs take structs by value) --

EMSCRIPTEN_KEEPALIVE
void wasm_free_ecurve(ecurve_ref* ref) {
  free_ecurve(*ref);
}

EMSCRIPTEN_KEEPALIVE
void wasm_free_ecc_point(ecc_point_ref* ref) {
  free_ecc_point(*ref);
}

EMSCRIPTEN_KEEPALIVE
void wasm_free_mpc_ecdsa2p_key(mpc_ecdsa2pc_key_ref* ref) {
  free_mpc_ecdsa2p_key(*ref);
}

EMSCRIPTEN_KEEPALIVE
void wasm_free_mpc_eckey_mp(mpc_eckey_mp_ref* ref) {
  free_mpc_eckey_mp(*ref);
}

// -- Curve wrappers --

EMSCRIPTEN_KEEPALIVE
void wasm_new_ecurve(int curve_code, ecurve_ref* out) {
  *out = new_ecurve(curve_code);
}

EMSCRIPTEN_KEEPALIVE
void wasm_ecurve_generator(ecurve_ref* curve, ecc_point_ref* out) {
  *out = ecurve_generator(curve);
}

EMSCRIPTEN_KEEPALIVE
void wasm_ecurve_order(ecurve_ref* curve, cmem_t* out) {
  *out = ecurve_order(curve);
}

EMSCRIPTEN_KEEPALIVE
void wasm_ecurve_random_scalar(ecurve_ref* curve, cmem_t* out) {
  *out = ecurve_random_scalar(curve);
}

EMSCRIPTEN_KEEPALIVE
void wasm_ecurve_mul_generator(ecurve_ref* curve, uint8_t* s_data, int s_size, ecc_point_ref* out) {
  cmem_t scalar = {s_data, s_size};
  *out = ecurve_mul_generator(curve, scalar);
}

// -- Point wrappers --

EMSCRIPTEN_KEEPALIVE
void wasm_ecc_point_from_bytes(uint8_t* data, int size, ecc_point_ref* out) {
  cmem_t point_bytes = {data, size};
  *out = ecc_point_from_bytes(point_bytes);
}

EMSCRIPTEN_KEEPALIVE
void wasm_ecc_point_to_bytes(ecc_point_ref* point, cmem_t* out) {
  *out = ecc_point_to_bytes(point);
}

EMSCRIPTEN_KEEPALIVE
void wasm_ecc_point_multiply(ecc_point_ref* point, uint8_t* s_data, int s_size, ecc_point_ref* out) {
  cmem_t scalar = {s_data, s_size};
  *out = ecc_point_multiply(point, scalar);
}

EMSCRIPTEN_KEEPALIVE
void wasm_ecc_point_add(ecc_point_ref* p1, ecc_point_ref* p2, ecc_point_ref* out) {
  *out = ecc_point_add(p1, p2);
}

EMSCRIPTEN_KEEPALIVE
void wasm_ecc_point_subtract(ecc_point_ref* p1, ecc_point_ref* p2, ecc_point_ref* out) {
  *out = ecc_point_subtract(p1, p2);
}

EMSCRIPTEN_KEEPALIVE
void wasm_ecc_point_get_x(ecc_point_ref* point, cmem_t* out) {
  *out = ecc_point_get_x(point);
}

EMSCRIPTEN_KEEPALIVE
void wasm_ecc_point_get_y(ecc_point_ref* point, cmem_t* out) {
  *out = ecc_point_get_y(point);
}

// -- Scalar wrappers --

EMSCRIPTEN_KEEPALIVE
void wasm_bn_add(uint8_t* a_data, int a_size, uint8_t* b_data, int b_size, cmem_t* out) {
  cmem_t a = {a_data, a_size};
  cmem_t b = {b_data, b_size};
  *out = bn_add(a, b);
}

EMSCRIPTEN_KEEPALIVE
void wasm_ec_mod_add(ecurve_ref* curve, uint8_t* a_data, int a_size, uint8_t* b_data, int b_size, cmem_t* out) {
  cmem_t a = {a_data, a_size};
  cmem_t b = {b_data, b_size};
  *out = ec_mod_add(curve, a, b);
}

EMSCRIPTEN_KEEPALIVE
void wasm_bn_from_int64(int64_t value, cmem_t* out) {
  *out = bn_from_int64(value);
}

// -- ECDSA 2P wrappers --

EMSCRIPTEN_KEEPALIVE
void wasm_mpc_ecdsa2p_key_get_Q(mpc_ecdsa2pc_key_ref* key, ecc_point_ref* out) {
  *out = mpc_ecdsa2p_key_get_Q(key);
}

EMSCRIPTEN_KEEPALIVE
void wasm_mpc_ecdsa2p_key_get_x_share(mpc_ecdsa2pc_key_ref* key, cmem_t* out) {
  *out = mpc_ecdsa2p_key_get_x_share(key);
}

// -- Verification wrapper --

EMSCRIPTEN_KEEPALIVE
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

EMSCRIPTEN_KEEPALIVE
void wasm_mpc_eckey_mp_get_Q(mpc_eckey_mp_ref* key, ecc_point_ref* out) {
  *out = mpc_eckey_mp_get_Q(key);
}

}  // extern "C"
