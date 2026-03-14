// WASM binding layer for cb-mpc.
//
// This file bridges the C API (from cgobinding/) to Emscripten/WASM,
// providing memory helpers and a callback-based data transport that
// delegates to JavaScript send/receive functions via ASYNCIFY.

#include <emscripten.h>

#include <cstdlib>
#include <cstring>

#include <cbmpc/core/cmem.h>

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
  const cb = Module._transportCallbacks[transport_id];
  if (!cb || !cb.send) return -1;
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

}  // extern "C"
