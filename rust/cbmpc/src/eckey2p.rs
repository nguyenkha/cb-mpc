// 2-party EC key share (cb-mpc eckey::key_share_2p_t) for Schnorr-2P EdDSA: DKG, signing,
// serialization in the cb-mpc-ts layout [role:int32, curve, Q, x_share].

use crate::curve::Point;
use crate::error::{check, clear_last_error, last_error, Error, Result};
use crate::mem::{take_cmem, take_cmems, view, CmemsIn};
use crate::transport::Job2p;
use cbmpc_sys::{cmem_t, cmems_t, mpc_eckey_2p_ref};
use zeroize::Zeroizing;

pub struct EcKey2p(mpc_eckey_2p_ref);

// SAFETY: as Ecdsa2pKey: an owned C++ object without thread affinity, not Sync.
unsafe impl Send for EcKey2p {}

impl EcKey2p {
    fn own(op: &'static str, r: mpc_eckey_2p_ref) -> Result<Self> {
        if r.opaque.is_null() {
            return Err(Error { op, code: -1 });
        }
        Ok(Self(r))
    }

    /// Runs the 2P EC-key DKG on `curve_code` (kexify: `NID_ED25519`).
    pub fn dkg(job: &mut Job2p<'_>, curve_code: i32) -> Result<Self> {
        let mut k = mpc_eckey_2p_ref {
            opaque: std::ptr::null_mut(),
        };
        // SAFETY: valid job; k receives an owned handle on success.
        let rv = unsafe { cbmpc_sys::mpc_eckey_2p_dkg(job.raw(), curve_code, &mut k) };
        job.finish("mpc_eckey_2p_dkg", rv)?;
        Self::own("mpc_eckey_2p_dkg", k)
    }

    /// Schnorr-2P EdDSA signature over the whole `message` (cb-mpc-ts `schnorr2pEddsaSign`).
    pub fn eddsa_sign(&self, job: &mut Job2p<'_>, message: &[u8]) -> Result<Vec<u8>> {
        job.check_role("mpc_schnorr2p_eddsa_sign", self.role_index()?)?;
        let mut sig = cmem_t {
            data: std::ptr::null_mut(),
            size: 0,
        };
        let mut r = self.0;
        // SAFETY: valid job and key; sig receives a malloc'ed buffer.
        let rv = unsafe {
            cbmpc_sys::mpc_schnorr2p_eddsa_sign(
                job.raw(),
                &mut r,
                view("mpc_schnorr2p_eddsa_sign", message)?,
                &mut sig,
            )
        };
        // SAFETY: library output, taken once.
        let out = unsafe { take_cmem(sig) };
        job.finish("mpc_schnorr2p_eddsa_sign", rv)?;
        Ok(out.to_vec())
    }

    /// Serialized parts in the cb-mpc-ts layout. Secret: wiped when dropped.
    pub fn serialize(&self) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        let mut ser = cmems_t {
            count: 0,
            data: std::ptr::null_mut(),
            sizes: std::ptr::null_mut(),
        };
        let mut r = self.0;
        // SAFETY: valid key; ser receives a malloc'ed list.
        let rv = unsafe { cbmpc_sys::serialize_mpc_eckey_2p(&mut r, &mut ser) };
        // SAFETY: library output, taken once.
        let parts = unsafe { take_cmems(ser) };
        check("serialize_mpc_eckey_2p", rv)?;
        Ok(parts)
    }

    /// Loads (and validates) a key from its serialized parts. The caller wipes `parts`.
    pub fn deserialize(parts: &[&[u8]]) -> Result<Self> {
        let mut input = CmemsIn::new("deserialize_mpc_eckey_2p", parts)?;
        let mut k = mpc_eckey_2p_ref {
            opaque: std::ptr::null_mut(),
        };
        // SAFETY: input lives for the call; k receives an owned handle on success.
        let rv = unsafe { cbmpc_sys::deserialize_mpc_eckey_2p(input.raw(), &mut k) };
        check("deserialize_mpc_eckey_2p", rv)?;
        Self::own("deserialize_mpc_eckey_2p", k)
    }

    pub fn role_index(&self) -> Result<i32> {
        let mut r = self.0;
        clear_last_error();
        // SAFETY: valid key.
        let v = unsafe { cbmpc_sys::mpc_eckey_2p_get_role_index(&mut r) };
        last_error("mpc_eckey_2p_get_role_index")?;
        Ok(v)
    }

    pub fn curve_code(&self) -> Result<i32> {
        let mut r = self.0;
        clear_last_error();
        // SAFETY: valid key.
        let v = unsafe { cbmpc_sys::mpc_eckey_2p_get_curve_code(&mut r) };
        last_error("mpc_eckey_2p_get_curve_code")?;
        Ok(v)
    }

    pub fn public_point(&self) -> Result<Point> {
        let mut r = self.0;
        clear_last_error();
        // SAFETY: valid key; returns an owned point.
        let p = unsafe { cbmpc_sys::mpc_eckey_2p_get_Q(&mut r) };
        Point::own("mpc_eckey_2p_get_Q", p)
    }

    /// Q as cb-mpc-ts `ecKey2pInfo().publicKey` (0x04 || X || Y, see `Point::to_sec1_like_ts`).
    pub fn public_key(&self) -> Result<Vec<u8>> {
        self.public_point()?.to_sec1_like_ts()
    }

    /// This party's secret share, big-endian. Secret.
    pub fn x_share(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut r = self.0;
        clear_last_error();
        // SAFETY: valid key; result malloc'ed, taken once.
        let out = unsafe { take_cmem(cbmpc_sys::mpc_eckey_2p_get_x_share(&mut r)) };
        last_error("mpc_eckey_2p_get_x_share")?;
        Ok(out)
    }
}

impl Drop for EcKey2p {
    fn drop(&mut self) {
        // SAFETY: owned handle, freed once.
        unsafe { cbmpc_sys::free_mpc_eckey_2p(self.0) };
    }
}
