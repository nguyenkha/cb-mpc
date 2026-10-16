// PVE (publicly verifiable encryption), batch, single recipient, ECIES P-256 base PKE: encrypt
// scalars to an encryption key so the holder can check them against x_i*G without decrypting.

use crate::error::{check, Result};
use crate::mem::{take_cmem, take_cmems, view, CmemsIn};
use cbmpc_sys::{cmem_t, cmems_t};
use zeroize::Zeroizing;

const NULL_CMEM: cmem_t = cmem_t { data: std::ptr::null_mut(), size: 0 };

/// A fresh (ek, dk) pair. `dk` is secret.
pub fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let (mut ek, mut dk) = (NULL_CMEM, NULL_CMEM);
    // SAFETY: both outputs receive malloc'ed buffers.
    let rv = unsafe { cbmpc_sys::pve_generate_ecies_p256_keypair(&mut ek, &mut dk) };
    // SAFETY: library output, taken once each.
    let (ek, dk) = unsafe { (take_cmem(ek), take_cmem(dk)) };
    check("pve_generate_ecies_p256_keypair", rv)?;
    Ok((ek.to_vec(), dk))
}

/// Encrypts `xs` (scalars on `curve_code`) to `ek` under `label`.
pub fn batch_encrypt(curve_code: i32, ek: &[u8], label: &[u8], xs: &[&[u8]]) -> Result<Vec<u8>> {
    let mut xs = CmemsIn::new("pve_batch_encrypt", xs)?;
    let mut ct = NULL_CMEM;
    // SAFETY: inputs live for the call; ct receives a malloc'ed buffer.
    let rv = unsafe {
        cbmpc_sys::pve_batch_encrypt(curve_code, view("pve_batch_encrypt", ek)?, view("pve_batch_encrypt", label)?, xs.raw(), &mut ct)
    };
    // SAFETY: library output, taken once.
    let ct = unsafe { take_cmem(ct) };
    check("pve_batch_encrypt", rv)?;
    Ok(ct.to_vec())
}

/// Ok when `ciphertext` encrypts scalars x_i with x_i*G == qs[i] under `ek` and `label`.
pub fn batch_verify(curve_code: i32, ek: &[u8], ciphertext: &[u8], qs: &[&[u8]], label: &[u8]) -> Result<()> {
    let mut qs = CmemsIn::new("pve_batch_verify", qs)?;
    // SAFETY: inputs live for the call and are only read.
    let rv = unsafe {
        cbmpc_sys::pve_batch_verify(
            curve_code,
            view("pve_batch_verify", ek)?,
            view("pve_batch_verify", ciphertext)?,
            qs.raw(),
            view("pve_batch_verify", label)?,
        )
    };
    check("pve_batch_verify", rv)
}

/// Decrypts the scalars (does not verify first). Secret.
pub fn batch_decrypt(curve_code: i32, dk: &[u8], ek: &[u8], ciphertext: &[u8], label: &[u8]) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let mut xs = cmems_t { count: 0, data: std::ptr::null_mut(), sizes: std::ptr::null_mut() };
    let op = "pve_batch_decrypt";
    // SAFETY: inputs live for the call; xs receives a malloc'ed list.
    let rv = unsafe { cbmpc_sys::pve_batch_decrypt(curve_code, view(op, dk)?, view(op, ek)?, view(op, ciphertext)?, view(op, label)?, &mut xs) };
    // SAFETY: library output, taken once.
    let xs = unsafe { take_cmems(xs) };
    check(op, rv)?;
    Ok(xs)
}
