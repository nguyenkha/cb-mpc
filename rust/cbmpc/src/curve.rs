// Curve and point helpers the 2P flows need (order, x*G, encodings, DER verify).

use crate::error::{clear_last_error, last_error, Error, Result};
use crate::mem::{take_cmem, view};
use cbmpc_sys::{ecc_point_ref, ecurve_ref};
use zeroize::Zeroizing;

pub use cbmpc_sys::{NID_ED25519, NID_SECP256K1, NID_X9_62_PRIME256V1};

pub struct Curve(ecurve_ref);

impl Curve {
    /// `code` is the OpenSSL NID (`NID_SECP256K1`, `NID_ED25519`, ...).
    pub fn new(code: i32) -> Result<Self> {
        clear_last_error();
        // SAFETY: returns an owned handle or a null one.
        let r = unsafe { cbmpc_sys::new_ecurve(code) };
        last_error("new_ecurve")?;
        if r.opaque.is_null() {
            return Err(Error { op: "new_ecurve", code: -1 });
        }
        Ok(Self(r))
    }

    /// The group order, big-endian.
    pub fn order(&self) -> Result<Vec<u8>> {
        let mut r = self.0;
        clear_last_error();
        // SAFETY: valid handle; the result is a malloc'ed buffer we take over.
        let out = unsafe { take_cmem(cbmpc_sys::ecurve_order(&mut r)) };
        last_error("ecurve_order")?;
        Ok(out.to_vec())
    }

    /// `scalar * G`. The scalar is only read.
    pub fn mul_generator(&self, scalar: &[u8]) -> Result<Point> {
        let mut r = self.0;
        clear_last_error();
        // SAFETY: valid handle and view; returns an owned point handle.
        let p = unsafe { cbmpc_sys::ecurve_mul_generator(&mut r, view("ecurve_mul_generator", scalar)?) };
        Point::own("ecurve_mul_generator", p)
    }
}

impl Drop for Curve {
    fn drop(&mut self) {
        // SAFETY: owned handle, freed once.
        unsafe { cbmpc_sys::free_ecurve(self.0) };
    }
}

pub struct Point(ecc_point_ref);

impl Point {
    pub(crate) fn own(op: &'static str, p: ecc_point_ref) -> Result<Self> {
        last_error(op)?;
        if p.opaque.is_null() {
            return Err(Error { op, code: -1 });
        }
        Ok(Self(p))
    }

    /// cb-mpc's own point encoding (`coinbase::ser`), what cb-mpc-ts `pointToBytes` returns.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.read("ecc_point_to_bytes", cbmpc_sys::ecc_point_to_bytes).map(|b| b.to_vec())
    }

    /// `0x04 || X || Y` exactly as cb-mpc-ts `pointToSec1` builds it: both coordinates left-padded to
    /// the longer of their two minimal big-endian lengths (so it is not always 32 bytes each).
    /// kexify stores and compares public keys in this form.
    pub fn to_sec1_like_ts(&self) -> Result<Vec<u8>> {
        let x = self.read("ecc_point_get_x", cbmpc_sys::ecc_point_get_x)?;
        let y = self.read("ecc_point_get_y", cbmpc_sys::ecc_point_get_y)?;
        let n = x.len().max(y.len());
        let mut out = vec![0u8; 1 + 2 * n];
        out[0] = 0x04;
        out[1 + n - x.len()..1 + n].copy_from_slice(&x);
        out[1 + 2 * n - y.len()..].copy_from_slice(&y);
        Ok(out)
    }

    fn read(
        &self,
        op: &'static str,
        f: unsafe extern "C" fn(*mut ecc_point_ref) -> cbmpc_sys::cmem_t,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut r = self.0;
        clear_last_error();
        // SAFETY: valid handle; result is a malloc'ed buffer we take over.
        let out = unsafe { take_cmem(f(&mut r)) };
        last_error(op)?;
        Ok(out)
    }
}

impl Drop for Point {
    fn drop(&mut self) {
        // SAFETY: owned handle, freed once.
        unsafe { cbmpc_sys::free_ecc_point(self.0) };
    }
}

/// True when the DER `signature` over `hash` verifies under `public_key` (SEC1 octets).
pub fn verify_der(curve_code: i32, public_key: &[u8], hash: &[u8], signature: &[u8]) -> Result<bool> {
    // SAFETY: views of live slices, only read.
    let rv = unsafe {
        cbmpc_sys::ecc_verify_der(curve_code, view("ecc_verify_der", public_key)?, view("ecc_verify_der", hash)?, view("ecc_verify_der", signature)?)
    };
    Ok(rv == 0)
}
