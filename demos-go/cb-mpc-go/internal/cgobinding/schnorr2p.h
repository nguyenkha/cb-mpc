#pragma once

#include <stdint.h>

#include <cbmpc/core/cmem.h>

#include "curve.h"
#include "network.h"

#ifdef __cplusplus
extern "C" {
#endif

// ------------------------- Type Wrappers ---------------------------
// Wrapper for coinbase::mpc::eckey::key_share_2p_t (used by Schnorr 2P)

typedef struct mpc_eckey_2p_ref {
  void* opaque;  // Opaque pointer to the C++ class instance
} mpc_eckey_2p_ref;

// ------------------------- Memory management -----------------------
void free_mpc_eckey_2p(mpc_eckey_2p_ref ctx);

// ------------------------- Function Wrappers -----------------------

// Two-party EC DKG (produces a key_share_2p_t, simpler than ecdsa2pc::key_t)
int mpc_eckey_2p_dkg(job_2p_ref* job, int curve, mpc_eckey_2p_ref* key);

// Two-party Schnorr EdDSA signing (single message)
int mpc_schnorr2p_eddsa_sign(job_2p_ref* job, mpc_eckey_2p_ref* key, cmem_t msg, cmem_t* sig);

// Key accessors
ecc_point_ref mpc_eckey_2p_get_Q(mpc_eckey_2p_ref* key);
cmem_t mpc_eckey_2p_get_x_share(mpc_eckey_2p_ref* key);
int mpc_eckey_2p_get_role_index(mpc_eckey_2p_ref* key);
int mpc_eckey_2p_get_curve_code(mpc_eckey_2p_ref* key);

#ifdef __cplusplus
}  // extern "C"
#endif
