/**
 * Single source of truth for the native C ABI used by the FFI backends.
 *
 * Every entry takes and returns only scalars and pointers ("ptr" = native
 * pointer passed as a JS number). Functions whose C form takes a struct or a
 * 64-bit integer by value are reached through their `wasm_*` pointer-only
 * wrappers in binding.cpp. Keep this in sync with native/exports.txt.
 */

export type FfiType = "ptr" | "i32" | "void";

export interface FfiSignature {
  args: readonly FfiType[];
  returns: FfiType;
}

const sig = (returns: FfiType, ...args: FfiType[]): FfiSignature => ({ args, returns });

export const FFI_SIGNATURES: Record<string, FfiSignature> = {
  // Platform info
  native_pointer_size: sig("i32"),
  native_cmem_size: sig("i32"),
  native_ref_size: sig("i32"),
  native_register_transport: sig("void", "ptr", "ptr", "ptr"),

  // Memory
  wasm_alloc: sig("ptr", "i32"),
  wasm_free: sig("void", "ptr"),
  wasm_new_cmem: sig("ptr", "ptr", "i32"),
  wasm_free_cmem: sig("void", "ptr"),
  wasm_free_cmems: sig("void", "ptr"),
  wasm_cmem_data: sig("ptr", "ptr"),
  wasm_cmem_size: sig("i32", "ptr"),
  wasm_cmems_count: sig("i32", "ptr"),
  wasm_cmems_get: sig("i32", "ptr", "i32", "ptr"),
  wasm_seed_random: sig("i32", "ptr", "i32"),

  // Curve
  wasm_new_ecurve: sig("i32", "i32", "ptr"),
  wasm_free_ecurve: sig("void", "ptr"),
  ecurve_get_curve_code: sig("i32", "ptr"),
  wasm_ecurve_generator: sig("i32", "ptr", "ptr"),
  wasm_ecurve_order: sig("i32", "ptr", "ptr"),
  wasm_ecurve_random_scalar: sig("i32", "ptr", "ptr"),
  wasm_ecurve_mul_generator: sig("i32", "ptr", "ptr", "i32", "ptr"),

  // Point
  wasm_free_ecc_point: sig("void", "ptr"),
  wasm_ecc_point_from_bytes: sig("i32", "ptr", "i32", "ptr"),
  wasm_ecc_point_to_bytes: sig("i32", "ptr", "ptr"),
  wasm_ecc_point_multiply: sig("i32", "ptr", "ptr", "i32", "ptr"),
  wasm_ecc_point_add: sig("i32", "ptr", "ptr", "ptr"),
  wasm_ecc_point_subtract: sig("i32", "ptr", "ptr", "ptr"),
  wasm_ecc_point_get_x: sig("i32", "ptr", "ptr"),
  wasm_ecc_point_get_y: sig("i32", "ptr", "ptr"),
  ecc_point_is_zero: sig("i32", "ptr"),
  ecc_point_equals: sig("i32", "ptr", "ptr"),

  // Scalar
  wasm_bn_add: sig("i32", "ptr", "i32", "ptr", "i32", "ptr"),
  wasm_ec_mod_add: sig("i32", "ptr", "ptr", "i32", "ptr", "i32", "ptr"),

  // Verification
  wasm_ecc_verify_der: sig("i32", "i32", "ptr", "i32", "ptr", "i32", "ptr", "i32"),

  // Jobs
  wasm_new_job_2p: sig("ptr", "i32", "i32", "ptr", "ptr"),
  wasm_new_job_mp: sig("ptr", "i32", "i32", "i32", "ptr", "i32"),
  free_job_2p: sig("void", "ptr"),
  free_job_mp: sig("void", "ptr"),
  is_peer1: sig("i32", "ptr"),
  is_peer2: sig("i32", "ptr"),
  get_role_index: sig("i32", "ptr"),
  get_party_idx: sig("i32", "ptr"),
  get_n_parties: sig("i32", "ptr"),

  // ECDSA 2P
  mpc_ecdsa2p_dkg: sig("i32", "ptr", "i32", "ptr"),
  mpc_ecdsa2p_refresh: sig("i32", "ptr", "ptr", "ptr"),
  wasm_mpc_ecdsa2p_sign: sig("i32", "ptr", "ptr", "ptr", "ptr", "ptr"),
  wasm_free_mpc_ecdsa2p_key: sig("void", "ptr"),
  mpc_ecdsa2p_key_get_role_index: sig("i32", "ptr"),
  mpc_ecdsa2p_key_get_curve_code: sig("i32", "ptr"),
  wasm_mpc_ecdsa2p_key_get_Q: sig("i32", "ptr", "ptr"),
  wasm_mpc_ecdsa2p_key_get_x_share: sig("i32", "ptr", "ptr"),
  serialize_mpc_ecdsa2p: sig("i32", "ptr", "ptr"),
  wasm_deserialize_mpc_ecdsa2p: sig("i32", "ptr", "ptr"),

  // EC key 2P / Schnorr 2P
  mpc_eckey_2p_dkg: sig("i32", "ptr", "i32", "ptr"),
  wasm_mpc_schnorr2p_eddsa_sign: sig("i32", "ptr", "ptr", "ptr", "i32", "ptr"),
  wasm_free_mpc_eckey_2p: sig("void", "ptr"),
  mpc_eckey_2p_get_role_index: sig("i32", "ptr"),
  mpc_eckey_2p_get_curve_code: sig("i32", "ptr"),
  wasm_mpc_eckey_2p_get_Q: sig("i32", "ptr", "ptr"),
  wasm_mpc_eckey_2p_get_x_share: sig("i32", "ptr", "ptr"),
  serialize_mpc_eckey_2p: sig("i32", "ptr", "ptr"),
  wasm_deserialize_mpc_eckey_2p: sig("i32", "ptr", "ptr"),

  // EC key MP
  mpc_eckey_mp_dkg: sig("i32", "ptr", "ptr", "ptr"),
  wasm_mpc_eckey_mp_refresh: sig("i32", "ptr", "ptr", "ptr", "ptr"),
  wasm_free_mpc_eckey_mp: sig("void", "ptr"),
  wasm_mpc_eckey_mp_get_Q: sig("i32", "ptr", "ptr"),
  mpc_eckey_mp_get_x_share: sig("i32", "ptr", "ptr"),
  mpc_eckey_mp_get_party_name: sig("i32", "ptr", "ptr"),
  serialize_mpc_eckey_mp: sig("i32", "ptr", "ptr"),
  wasm_deserialize_mpc_eckey_mp: sig("i32", "ptr", "ptr"),

  // ECDSA MP / EdDSA MP
  wasm_mpc_ecdsampc_sign: sig("i32", "ptr", "ptr", "ptr", "i32", "ptr"),
  wasm_mpc_eddsampc_sign: sig("i32", "ptr", "ptr", "ptr", "i32", "ptr"),

  // ZK (aux passed as two uint32 halves)
  wasm_zk_dl_prove: sig("i32", "ptr", "ptr", "ptr", "i32", "i32", "ptr"),
  wasm_zk_dl_verify: sig("i32", "ptr", "ptr", "ptr", "i32", "i32"),

  // PVE
  pve_generate_ecies_p256_keypair: sig("i32", "ptr", "ptr"),
  wasm_pve_batch_encrypt: sig("i32", "i32", "ptr", "ptr", "ptr", "ptr"),
  wasm_pve_batch_verify: sig("i32", "i32", "ptr", "ptr", "ptr", "ptr"),
  wasm_pve_batch_decrypt: sig("i32", "i32", "ptr", "ptr", "ptr", "ptr", "ptr"),

  // Access-structure keys
  wasm_mpc_ac_dkg: sig("i32", "ptr", "i32", "ptr", "ptr", "ptr"),
  wasm_mpc_ac_refresh: sig("i32", "ptr", "ptr", "ptr", "ptr", "ptr"),
  wasm_mpc_ac_sign: sig("i32", "ptr", "ptr", "ptr", "ptr", "i32", "ptr"),
  wasm_mpc_ac_reshare_from_additive: sig("i32", "ptr", "i32", "ptr", "ptr", "ptr", "ptr", "ptr"),
  wasm_mpc_ac_to_additive_share: sig("i32", "ptr", "ptr", "ptr", "ptr"),
  wasm_mpc_ac_key_info: sig("i32", "ptr", "ptr", "ptr"),

  // Agree random
  mpc_agree_random: sig("i32", "ptr", "i32", "ptr"),
};

/** C type used for an FfiType in koffi prototypes (pointers as intptr_t so JS numbers work). */
export const KOFFI_C_TYPE: Record<FfiType, string> = { ptr: "intptr_t", i32: "int", void: "void" };
