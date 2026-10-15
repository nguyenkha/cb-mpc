#pragma once

// HD keysets (2-party, ECDSA and EdDSA) for the cb-mpc-ts C ABI.
//
// Fork-owned extension: everything lives under cb-mpc-ts/ and only calls
// upstream's internal protocol code, so upstream merges never touch it.
//
// Upstream's HD scheme ("MPC-friendly derivation", see docs/theory/
// mpc-friendly-derivation-theory.pdf): a keyset holds the signing key share
// (x, Q) plus a VRF key share (k, K). Hardened derivation is a 2-party DH-based
// PRF step; non-hardened derivation is plain BIP32 CKDpub from the resulting
// account node. Derived keys are ordinary ECDSA-2P / EdDSA-2P key handles.
//
// Paths cross the ABI as big-endian uint32 arrays: a path of n indices is a
// buffer of 4*n bytes. A list of paths is a cmems_t, one entry per path.
// All arguments are scalars or pointers (FFI-portable).

#include "cbmpc_ts.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mpc_hd_ecdsa2p_ref {
  void* opaque;
} mpc_hd_ecdsa2p_ref;

typedef struct mpc_hd_eddsa2p_ref {
  void* opaque;
} mpc_hd_eddsa2p_ref;

// ---------------------------------------------------------------------------
// ECDSA-2P keysets (secp256k1, P-256)
// ---------------------------------------------------------------------------

// Fresh keyset (signing key DKG incl. Paillier + VRF key DKG).
int mpc_hd_ecdsa2p_dkg(job_2p_ref* job, int curve_code, mpc_hd_ecdsa2p_ref* out);
// Upgrade an existing ECDSA-2P key into a keyset: runs only a VRF key DKG; the
// signing key (and so the root public key / address) is unchanged. Both
// parties must pass shares of the same key (checked).
int mpc_hd_ecdsa2p_from_key(job_2p_ref* job, mpc_ecdsa2pc_key_ref* key, mpc_hd_ecdsa2p_ref* out);
int mpc_hd_ecdsa2p_refresh(job_2p_ref* job, mpc_hd_ecdsa2p_ref* keyset, mpc_hd_ecdsa2p_ref* out);
// Derive ECDSA-2P keys for `hardened_path` + each entry of `non_hardened_paths`
// in one protocol run. `out_keys` points to `count` key refs (count must equal
// non_hardened_paths->count). `sid` may be empty.
int mpc_hd_ecdsa2p_derive(job_2p_ref* job, mpc_hd_ecdsa2p_ref* keyset, cmem_t* hardened_path,
                          cmems_t* non_hardened_paths, cmem_t* sid, mpc_ecdsa2pc_key_ref* out_keys, int count);
// Account node after the hardened step: compressed public key and 32-byte
// chain code. For secp256k1 this is a BIP32 extended public key (xpub) whose
// non-hardened children match mpc_hd_ecdsa2p_derive.
int mpc_hd_ecdsa2p_account_node(job_2p_ref* job, mpc_hd_ecdsa2p_ref* keyset, cmem_t* hardened_path, cmem_t* sid,
                                cmem_t* out_public_key, cmem_t* out_chain_code);
int mpc_hd_ecdsa2p_get_Q(mpc_hd_ecdsa2p_ref* keyset, ecc_point_ref* out);
int mpc_hd_ecdsa2p_get_role_index(mpc_hd_ecdsa2p_ref* keyset);
int mpc_hd_ecdsa2p_get_curve_code(mpc_hd_ecdsa2p_ref* keyset);
int serialize_mpc_hd_ecdsa2p(mpc_hd_ecdsa2p_ref* keyset, cmems_t* ser);
int deserialize_mpc_hd_ecdsa2p(cmems_t* ser, mpc_hd_ecdsa2p_ref* out);
void free_mpc_hd_ecdsa2p(mpc_hd_ecdsa2p_ref* keyset);

// ---------------------------------------------------------------------------
// EdDSA-2P keysets (Ed25519)
// ---------------------------------------------------------------------------

int mpc_hd_eddsa2p_dkg(job_2p_ref* job, int curve_code, mpc_hd_eddsa2p_ref* out);
int mpc_hd_eddsa2p_from_key(job_2p_ref* job, mpc_eckey_2p_ref* key, mpc_hd_eddsa2p_ref* out);
int mpc_hd_eddsa2p_refresh(job_2p_ref* job, mpc_hd_eddsa2p_ref* keyset, mpc_hd_eddsa2p_ref* out);
int mpc_hd_eddsa2p_derive(job_2p_ref* job, mpc_hd_eddsa2p_ref* keyset, cmem_t* hardened_path,
                          cmems_t* non_hardened_paths, cmem_t* sid, mpc_eckey_2p_ref* out_keys, int count);
// Same construction as ECDSA, but there is no Ed25519 BIP32 standard: the node
// is only usable with this library's derivation (not SLIP-10 / BIP32-Ed25519).
int mpc_hd_eddsa2p_account_node(job_2p_ref* job, mpc_hd_eddsa2p_ref* keyset, cmem_t* hardened_path, cmem_t* sid,
                                cmem_t* out_public_key, cmem_t* out_chain_code);
int mpc_hd_eddsa2p_get_Q(mpc_hd_eddsa2p_ref* keyset, ecc_point_ref* out);
int mpc_hd_eddsa2p_get_role_index(mpc_hd_eddsa2p_ref* keyset);
int mpc_hd_eddsa2p_get_curve_code(mpc_hd_eddsa2p_ref* keyset);
int serialize_mpc_hd_eddsa2p(mpc_hd_eddsa2p_ref* keyset, cmems_t* ser);
int deserialize_mpc_hd_eddsa2p(cmems_t* ser, mpc_hd_eddsa2p_ref* out);
void free_mpc_hd_eddsa2p(mpc_hd_eddsa2p_ref* keyset);

#ifdef __cplusplus
}  // extern "C"
#endif
