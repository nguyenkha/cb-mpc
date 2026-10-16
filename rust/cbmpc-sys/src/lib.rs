//! Raw declarations for the cb-mpc-ts C ABI (`cb-mpc-ts/capi/cbmpc_ts.h`), the subset the 2-party
//! ECDSA / EdDSA (Schnorr) protocols, curve helpers and PVE need. Use the safe `cbmpc` crate.
//!
//! Memory contract (see the header): every `cmem_t` / `cmems_t` the library returns is `malloc`ed and
//! must be released with `free` (`cmems_t`: both `data` and `sizes`). Buffers a `receive_f` callback
//! returns must be `malloc`ed too; the library wipes and frees them.
#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_void};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct cmem_t {
    pub data: *mut u8,
    pub size: c_int,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct cmems_t {
    pub count: c_int,
    pub data: *mut u8,
    pub sizes: *mut c_int,
}

macro_rules! opaque_ref {
    ($($name:ident),*) => {$(
        #[repr(C)]
        #[derive(Debug, Clone, Copy)]
        pub struct $name {
            pub opaque: *mut c_void,
        }
    )*};
}
opaque_ref!(ecurve_ref, ecc_point_ref, job_2p_ref, mpc_ecdsa2pc_key_ref, mpc_eckey_2p_ref);

pub type send_f = unsafe extern "C" fn(ctx: *mut c_void, receiver: c_int, message: cmem_t) -> c_int;
pub type receive_f = unsafe extern "C" fn(ctx: *mut c_void, sender: c_int, message: *mut cmem_t) -> c_int;
pub type receive_all_f =
    unsafe extern "C" fn(ctx: *mut c_void, senders: *mut c_int, sender_count: c_int, messages: *mut cmems_t) -> c_int;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct data_transport_callbacks_t {
    pub send_fun: Option<send_f>,
    pub receive_fun: Option<receive_f>,
    pub receive_all_fun: Option<receive_all_f>,
}

pub const NETWORK_SUCCESS: c_int = 0;
pub const NETWORK_ERROR: c_int = -1;
pub const NETWORK_PARAM_ERROR: c_int = -2;
pub const NETWORK_MEMORY_ERROR: c_int = -3;
pub const NETWORK_INVALID_STATE: c_int = -4;

/// OpenSSL NIDs of the curves kexify uses.
pub const NID_SECP256K1: c_int = 714;
pub const NID_X9_62_PRIME256V1: c_int = 415;
pub const NID_ED25519: c_int = 1087;

extern "C" {
    pub fn cbmpc_ts_take_last_error() -> c_int;

    // Jobs
    pub fn new_job_2p(
        callbacks: *const data_transport_callbacks_t,
        ctx: *mut c_void,
        party_index: c_int,
        pnames: *const *const c_char,
        pname_count: c_int,
    ) -> *mut job_2p_ref;
    pub fn free_job_2p(ptr: *mut job_2p_ref);

    // Curves and points
    pub fn new_ecurve(curve_code: c_int) -> ecurve_ref;
    pub fn free_ecurve(r: ecurve_ref);
    pub fn ecurve_order(curve: *mut ecurve_ref) -> cmem_t;
    pub fn ecurve_mul_generator(curve: *mut ecurve_ref, scalar: cmem_t) -> ecc_point_ref;
    pub fn free_ecc_point(r: ecc_point_ref);
    pub fn ecc_point_to_bytes(point: *mut ecc_point_ref) -> cmem_t;
    pub fn ecc_point_get_x(point: *mut ecc_point_ref) -> cmem_t;
    pub fn ecc_point_get_y(point: *mut ecc_point_ref) -> cmem_t;
    pub fn ecc_verify_der(curve_code: c_int, pub_oct: cmem_t, hash: cmem_t, der_sig: cmem_t) -> c_int;

    // ECDSA 2P
    pub fn mpc_ecdsa2p_dkg(job: *mut job_2p_ref, curve_code: c_int, key: *mut mpc_ecdsa2pc_key_ref) -> c_int;
    pub fn mpc_ecdsa2p_sign(
        job: *mut job_2p_ref,
        sid: cmem_t,
        key: *mut mpc_ecdsa2pc_key_ref,
        msgs: cmems_t,
        sigs: *mut cmems_t,
    ) -> c_int;
    pub fn free_mpc_ecdsa2p_key(key: mpc_ecdsa2pc_key_ref);
    pub fn mpc_ecdsa2p_key_get_role_index(key: *mut mpc_ecdsa2pc_key_ref) -> c_int;
    pub fn mpc_ecdsa2p_key_get_Q(key: *mut mpc_ecdsa2pc_key_ref) -> ecc_point_ref;
    pub fn mpc_ecdsa2p_key_get_x_share(key: *mut mpc_ecdsa2pc_key_ref) -> cmem_t;
    pub fn mpc_ecdsa2p_key_get_curve_code(key: *mut mpc_ecdsa2pc_key_ref) -> c_int;
    pub fn serialize_mpc_ecdsa2p(key: *mut mpc_ecdsa2pc_key_ref, ser: *mut cmems_t) -> c_int;
    pub fn deserialize_mpc_ecdsa2p(ser: cmems_t, key: *mut mpc_ecdsa2pc_key_ref) -> c_int;

    // EC key 2P / Schnorr 2P (EdDSA)
    pub fn mpc_eckey_2p_dkg(job: *mut job_2p_ref, curve_code: c_int, key: *mut mpc_eckey_2p_ref) -> c_int;
    pub fn mpc_schnorr2p_eddsa_sign(job: *mut job_2p_ref, key: *mut mpc_eckey_2p_ref, msg: cmem_t, sig: *mut cmem_t) -> c_int;
    pub fn free_mpc_eckey_2p(key: mpc_eckey_2p_ref);
    pub fn mpc_eckey_2p_get_role_index(key: *mut mpc_eckey_2p_ref) -> c_int;
    pub fn mpc_eckey_2p_get_Q(key: *mut mpc_eckey_2p_ref) -> ecc_point_ref;
    pub fn mpc_eckey_2p_get_x_share(key: *mut mpc_eckey_2p_ref) -> cmem_t;
    pub fn mpc_eckey_2p_get_curve_code(key: *mut mpc_eckey_2p_ref) -> c_int;
    pub fn serialize_mpc_eckey_2p(key: *mut mpc_eckey_2p_ref, ser: *mut cmems_t) -> c_int;
    pub fn deserialize_mpc_eckey_2p(ser: cmems_t, key: *mut mpc_eckey_2p_ref) -> c_int;

    // PVE (publicly verifiable encryption), batch, single recipient, ECIES P-256 base PKE
    pub fn pve_generate_ecies_p256_keypair(ek: *mut cmem_t, dk: *mut cmem_t) -> c_int;
    pub fn pve_batch_encrypt(curve_code: c_int, ek: cmem_t, label: cmem_t, xs: cmems_t, ciphertext: *mut cmem_t) -> c_int;
    pub fn pve_batch_verify(curve_code: c_int, ek: cmem_t, ciphertext: cmem_t, qs_compressed: cmems_t, label: cmem_t) -> c_int;
    pub fn pve_batch_decrypt(
        curve_code: c_int,
        dk: cmem_t,
        ek: cmem_t,
        ciphertext: cmem_t,
        label: cmem_t,
        xs: *mut cmems_t,
    ) -> c_int;
}
