// 2-party ECDSA key share (cb-mpc ecdsa2pc::key_t): DKG, batch signing, serialization in the
// cb-mpc-ts layout [role:int32, curve, Q, x_share, c_key, paillier] (what kexify stores).

use crate::curve::Point;
use crate::error::{clear_last_error, last_error, Error, Result};
use crate::mem::{take_cmem, take_cmems, view, CmemsIn};
use crate::transport::Job2p;
use cbmpc_sys::{cmems_t, mpc_ecdsa2pc_key_ref};
use zeroize::Zeroizing;

pub struct Ecdsa2pKey(mpc_ecdsa2pc_key_ref);

// SAFETY: the handle owns a plain C++ object with no thread affinity. The type is not Sync, so it
// is used by one thread at a time; moving it to a protocol thread is fine.
unsafe impl Send for Ecdsa2pKey {}

impl Ecdsa2pKey {
    fn own(op: &'static str, r: mpc_ecdsa2pc_key_ref) -> Result<Self> {
        if r.opaque.is_null() {
            return Err(Error { op, code: -1 });
        }
        Ok(Self(r))
    }

    /// Runs the 2P DKG as this job's party on curve `curve_code` (e.g. `NID_SECP256K1`).
    pub fn dkg(job: &mut Job2p<'_>, curve_code: i32) -> Result<Self> {
        let mut k = mpc_ecdsa2pc_key_ref {
            opaque: std::ptr::null_mut(),
        };
        // SAFETY: valid job; k receives an owned handle on success.
        let rv = unsafe { cbmpc_sys::mpc_ecdsa2p_dkg(job.raw(), curve_code, &mut k) };
        job.finish("mpc_ecdsa2p_dkg", rv)?;
        Self::own("mpc_ecdsa2p_dkg", k)
    }

    /// Signs all `hashes` in one session (`sign_batch`, same as cb-mpc-ts `ecdsa2pSign`) with the
    /// shared session id `sid`. Returns the DER signatures this party ends with (the kexify server,
    /// P2, returns them to the API today).
    pub fn sign(&self, job: &mut Job2p<'_>, sid: &[u8], hashes: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
        let mut msgs = CmemsIn::new("mpc_ecdsa2p_sign", hashes)?;
        let mut sigs = cmems_t {
            count: 0,
            data: std::ptr::null_mut(),
            sizes: std::ptr::null_mut(),
        };
        let mut r = self.0;
        // SAFETY: valid job and key; inputs live for the call; sigs receives a malloc'ed list.
        let rv = unsafe {
            cbmpc_sys::mpc_ecdsa2p_sign(
                job.raw(),
                view("mpc_ecdsa2p_sign", sid)?,
                &mut r,
                msgs.raw(),
                &mut sigs,
            )
        };
        // SAFETY: sigs is library output (or empty); taken over exactly once.
        let out = unsafe { take_cmems(sigs) };
        job.finish("mpc_ecdsa2p_sign", rv)?;
        Ok(out.into_iter().map(|s| s.to_vec()).collect())
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
        let rv = unsafe { cbmpc_sys::serialize_mpc_ecdsa2p(&mut r, &mut ser) };
        // SAFETY: library output, taken once.
        let parts = unsafe { take_cmems(ser) };
        crate::error::check("serialize_mpc_ecdsa2p", rv)?;
        Ok(parts)
    }

    /// Loads (and validates) a key from its serialized parts. The caller wipes `parts`.
    pub fn deserialize(parts: &[&[u8]]) -> Result<Self> {
        let mut input = CmemsIn::new("deserialize_mpc_ecdsa2p", parts)?;
        let mut k = mpc_ecdsa2pc_key_ref {
            opaque: std::ptr::null_mut(),
        };
        // SAFETY: input lives for the call; k receives an owned handle on success.
        let rv = unsafe { cbmpc_sys::deserialize_mpc_ecdsa2p(input.raw(), &mut k) };
        crate::error::check("deserialize_mpc_ecdsa2p", rv)?;
        Self::own("deserialize_mpc_ecdsa2p", k)
    }

    /// 0 = P1, 1 = P2.
    pub fn role_index(&self) -> Result<i32> {
        let mut r = self.0;
        clear_last_error();
        // SAFETY: valid key.
        let v = unsafe { cbmpc_sys::mpc_ecdsa2p_key_get_role_index(&mut r) };
        last_error("mpc_ecdsa2p_key_get_role_index")?;
        Ok(v)
    }

    pub fn curve_code(&self) -> Result<i32> {
        let mut r = self.0;
        clear_last_error();
        // SAFETY: valid key.
        let v = unsafe { cbmpc_sys::mpc_ecdsa2p_key_get_curve_code(&mut r) };
        last_error("mpc_ecdsa2p_key_get_curve_code")?;
        Ok(v)
    }

    /// The joint public key Q.
    pub fn public_point(&self) -> Result<Point> {
        let mut r = self.0;
        clear_last_error();
        // SAFETY: valid key; returns an owned point.
        let p = unsafe { cbmpc_sys::mpc_ecdsa2p_key_get_Q(&mut r) };
        Point::own("mpc_ecdsa2p_key_get_Q", p)
    }

    /// Q as cb-mpc-ts `ecdsa2pKeyInfo().publicKey` (see `Point::to_sec1_like_ts`).
    pub fn public_key(&self) -> Result<Vec<u8>> {
        self.public_point()?.to_sec1_like_ts()
    }

    /// This party's secret share x_i, big-endian, as cb-mpc-ts `xShare`. Secret.
    pub fn x_share(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut r = self.0;
        clear_last_error();
        // SAFETY: valid key; result malloc'ed, taken once.
        let out = unsafe { take_cmem(cbmpc_sys::mpc_ecdsa2p_key_get_x_share(&mut r)) };
        last_error("mpc_ecdsa2p_key_get_x_share")?;
        Ok(out)
    }
}

impl Drop for Ecdsa2pKey {
    fn drop(&mut self) {
        // SAFETY: owned handle, freed once.
        unsafe { cbmpc_sys::free_mpc_ecdsa2p_key(self.0) };
    }
}
