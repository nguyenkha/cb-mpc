#pragma once

// C ABI used by the cb-mpc-ts bindings (WASM + native FFI).
//
// This layer replaces the Go cgobinding that upstream removed. It keeps the
// exact symbol names, signatures and key serialization layout of that layer so
// that the TypeScript API and previously serialized keys stay compatible.
// It is implemented directly on top of upstream's internal C++ protocol API.

#include <stdint.h>
#include <stdlib.h>

#include <cbmpc/c_api/cmem.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Error codes (network helpers)
// ---------------------------------------------------------------------------

#define NETWORK_SUCCESS 0
#define NETWORK_ERROR -1
#define NETWORK_PARAM_ERROR -2
#define NETWORK_MEMORY_ERROR -3
#define NETWORK_INVALID_STATE -4

// ---------------------------------------------------------------------------
// Opaque handle types
// ---------------------------------------------------------------------------

typedef struct ecurve_ref {
  void* opaque;
} ecurve_ref;

typedef struct ecc_point_ref {
  void* opaque;
} ecc_point_ref;

typedef struct job_2p_ref {
  void* opaque;
} job_2p_ref;

typedef struct job_mp_ref {
  void* opaque;
} job_mp_ref;

typedef struct mpc_party_set_ref {
  void* opaque;
} mpc_party_set_ref;

typedef struct mpc_ecdsa2pc_key_ref {
  void* opaque;
} mpc_ecdsa2pc_key_ref;

typedef struct mpc_eckey_2p_ref {
  void* opaque;
} mpc_eckey_2p_ref;

typedef struct mpc_eckey_mp_ref {
  void* opaque;
} mpc_eckey_mp_ref;

// ---------------------------------------------------------------------------
// Transport callbacks
// ---------------------------------------------------------------------------

// Buffers returned by `receive_fun` / `receive_all_fun` must be allocated with
// malloc(); the library copies and frees them.
typedef int (*send_f)(void* ctx, int receiver, cmem_t message);
typedef int (*receive_f)(void* ctx, int sender, cmem_t* message);
typedef int (*receive_all_f)(void* ctx, int* senders, int sender_count, cmems_t* messages);

typedef struct data_transport_callbacks_t {
  send_f send_fun;
  receive_f receive_fun;
  receive_all_f receive_all_fun;
} data_transport_callbacks_t;

// Returns and clears the error recorded by the last call on this thread that
// returns a value without a status code (curve/point/scalar helpers, key
// getters). 0 means the call succeeded.
int cbmpc_ts_take_last_error(void);

// ---------------------------------------------------------------------------
// Jobs and party sets
// ---------------------------------------------------------------------------

job_2p_ref* new_job_2p(const data_transport_callbacks_t* callbacks, void* ctx, int party_index,
                       const char* const* pnames, int pname_count);
void free_job_2p(job_2p_ref* ptr);
int is_peer1(const job_2p_ref* job);
int is_peer2(const job_2p_ref* job);
int get_role_index(const job_2p_ref* job);

job_mp_ref* new_job_mp(const data_transport_callbacks_t* callbacks, void* ctx, int party_count, int party_index,
                       const char* const* pnames, int pname_count);
void free_job_mp(job_mp_ref* ptr);
int get_party_idx(const job_mp_ref* job);
int get_n_parties(const job_mp_ref* job);

mpc_party_set_ref new_party_set(void);
void party_set_add(mpc_party_set_ref* set, int party_idx);
void free_party_set(mpc_party_set_ref ctx);

// ---------------------------------------------------------------------------
// Curves, points and scalars
// ---------------------------------------------------------------------------

ecurve_ref new_ecurve(int curve_code);
void free_ecurve(ecurve_ref ref);
ecc_point_ref ecurve_generator(ecurve_ref* curve);
cmem_t ecurve_order(ecurve_ref* curve);
int ecurve_get_curve_code(ecurve_ref* curve);
cmem_t ecurve_random_scalar(ecurve_ref* curve);
ecc_point_ref ecurve_mul_generator(ecurve_ref* curve, cmem_t scalar);

void free_ecc_point(ecc_point_ref ref);
ecc_point_ref ecc_point_from_bytes(cmem_t point_bytes);
cmem_t ecc_point_to_bytes(ecc_point_ref* point);
ecc_point_ref ecc_point_multiply(ecc_point_ref* point, cmem_t scalar);
ecc_point_ref ecc_point_add(ecc_point_ref* point1, ecc_point_ref* point2);
ecc_point_ref ecc_point_subtract(ecc_point_ref* point1, ecc_point_ref* point2);
cmem_t ecc_point_get_x(ecc_point_ref* point);
cmem_t ecc_point_get_y(ecc_point_ref* point);
int ecc_point_is_zero(ecc_point_ref* point);
int ecc_point_equals(ecc_point_ref* point1, ecc_point_ref* point2);

// Returns 0 when the DER signature verifies, non-zero otherwise.
int ecc_verify_der(int curve_code, cmem_t pub_oct, cmem_t hash, cmem_t der_sig);

cmem_t bn_add(cmem_t a, cmem_t b);
cmem_t ec_mod_add(ecurve_ref* curve, cmem_t a, cmem_t b);
cmem_t bn_from_int64(int64_t value);

// ---------------------------------------------------------------------------
// ECDSA 2P
// ---------------------------------------------------------------------------

int mpc_ecdsa2p_dkg(job_2p_ref* job, int curve_code, mpc_ecdsa2pc_key_ref* key);
int mpc_ecdsa2p_refresh(job_2p_ref* job, mpc_ecdsa2pc_key_ref* key, mpc_ecdsa2pc_key_ref* new_key);
int mpc_ecdsa2p_sign(job_2p_ref* job, cmem_t sid, mpc_ecdsa2pc_key_ref* key, cmems_t msgs, cmems_t* sigs);
void free_mpc_ecdsa2p_key(mpc_ecdsa2pc_key_ref key);
int mpc_ecdsa2p_key_get_role_index(mpc_ecdsa2pc_key_ref* key);
ecc_point_ref mpc_ecdsa2p_key_get_Q(mpc_ecdsa2pc_key_ref* key);
cmem_t mpc_ecdsa2p_key_get_x_share(mpc_ecdsa2pc_key_ref* key);
int mpc_ecdsa2p_key_get_curve_code(mpc_ecdsa2pc_key_ref* key);
int serialize_mpc_ecdsa2p(mpc_ecdsa2pc_key_ref* key, cmems_t* ser);
int deserialize_mpc_ecdsa2p(cmems_t ser, mpc_ecdsa2pc_key_ref* key);

// ---------------------------------------------------------------------------
// EC key 2P / Schnorr 2P
// ---------------------------------------------------------------------------

int mpc_eckey_2p_dkg(job_2p_ref* job, int curve_code, mpc_eckey_2p_ref* key);
int mpc_schnorr2p_eddsa_sign(job_2p_ref* job, mpc_eckey_2p_ref* key, cmem_t msg, cmem_t* sig);
void free_mpc_eckey_2p(mpc_eckey_2p_ref key);
int mpc_eckey_2p_get_role_index(mpc_eckey_2p_ref* key);
ecc_point_ref mpc_eckey_2p_get_Q(mpc_eckey_2p_ref* key);
cmem_t mpc_eckey_2p_get_x_share(mpc_eckey_2p_ref* key);
int mpc_eckey_2p_get_curve_code(mpc_eckey_2p_ref* key);
int serialize_mpc_eckey_2p(mpc_eckey_2p_ref* key, cmems_t* ser);
int deserialize_mpc_eckey_2p(cmems_t ser, mpc_eckey_2p_ref* key);

// ---------------------------------------------------------------------------
// EC key MP, ECDSA MP, EdDSA MP
// ---------------------------------------------------------------------------

int mpc_eckey_mp_dkg(job_mp_ref* job, ecurve_ref* curve, mpc_eckey_mp_ref* key);
int mpc_eckey_mp_refresh(job_mp_ref* job, cmem_t sid, mpc_eckey_mp_ref* key, mpc_eckey_mp_ref* new_key);
void free_mpc_eckey_mp(mpc_eckey_mp_ref key);
int mpc_eckey_mp_get_party_name(mpc_eckey_mp_ref* key, cmem_t* party_name);
int mpc_eckey_mp_get_x_share(mpc_eckey_mp_ref* key, cmem_t* x_share);
ecc_point_ref mpc_eckey_mp_get_Q(mpc_eckey_mp_ref* key);
ecurve_ref mpc_eckey_mp_get_curve(mpc_eckey_mp_ref* key);
int serialize_mpc_eckey_mp(mpc_eckey_mp_ref* key, cmems_t* ser);
int deserialize_mpc_eckey_mp(cmems_t ser, mpc_eckey_mp_ref* key);

int mpc_ecdsampc_sign(job_mp_ref* job, mpc_eckey_mp_ref* key, cmem_t msg, int sig_receiver, cmem_t* sig);
int mpc_eddsampc_sign(job_mp_ref* job, mpc_eckey_mp_ref* key, cmem_t msg, int sig_receiver, cmem_t* sig);

// ---------------------------------------------------------------------------
// ZK and agree-random
// ---------------------------------------------------------------------------

int zk_dl_prove(ecc_point_ref* Q, cmem_t w, cmem_t sid, uint64_t aux, cmem_t* proof);
int zk_dl_verify(ecc_point_ref* Q, cmem_t proof, cmem_t sid, uint64_t aux);

int mpc_agree_random(job_2p_ref* job, int bit_len, cmem_t* out);

// ---------------------------------------------------------------------------
// PVE (publicly verifiable encryption), batch, single recipient
// ---------------------------------------------------------------------------
// Uses cbmpc's built-in ECIES (P-256) base PKE. `curve_code` is the OpenSSL NID
// of the curve the encrypted scalars live on (secp256k1, P-256 or Ed25519).
// Returned buffers are malloc'ed; free them like any other cmem_t / cmems_t.

int pve_generate_ecies_p256_keypair(cmem_t* ek, cmem_t* dk);
int pve_batch_encrypt(int curve_code, cmem_t ek, cmem_t label, cmems_t xs, cmem_t* ciphertext);
// Returns 0 when `ciphertext` encrypts scalars x_i with x_i*G == Qs[i] under `ek` and `label`.
// Qs[i] may be a point from ecc_point_to_bytes or a raw compressed encoding.
int pve_batch_verify(int curve_code, cmem_t ek, cmem_t ciphertext, cmems_t Qs_compressed, cmem_t label);
// Does not verify the ciphertext first; call pve_batch_verify when that matters.
int pve_batch_decrypt(int curve_code, cmem_t dk, cmem_t ek, cmem_t ciphertext, cmem_t label, cmems_t* xs);

#ifdef __cplusplus
}  // extern "C"
#endif
