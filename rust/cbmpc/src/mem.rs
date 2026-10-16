// Moving bytes across the C ABI. Inputs are borrowed views (or one flat, zeroized copy for lists);
// outputs the library malloc'ed are copied into `Zeroizing` buffers and the C copy is wiped before
// `free`, so no secret byte is left in freed memory on either side.

use crate::error::{Error, Result, TOO_LARGE};
use cbmpc_sys::{cmem_t, cmems_t};
use std::os::raw::c_int;
use zeroize::{Zeroize, Zeroizing};

pub(crate) fn len_of(op: &'static str, n: usize) -> Result<c_int> {
    c_int::try_from(n).map_err(|_| Error { op, code: TOO_LARGE })
}

/// A view of `bytes` for a call that only reads it.
pub(crate) fn view(op: &'static str, bytes: &[u8]) -> Result<cmem_t> {
    Ok(cmem_t { data: bytes.as_ptr() as *mut u8, size: len_of(op, bytes.len())? })
}

/// A list of byte slices in the ABI's flat layout. The flat copy is wiped on drop.
pub(crate) struct CmemsIn {
    flat: Zeroizing<Vec<u8>>,
    sizes: Vec<c_int>,
}

impl CmemsIn {
    pub(crate) fn new(op: &'static str, parts: &[&[u8]]) -> Result<Self> {
        let total = parts.iter().map(|p| p.len()).sum();
        len_of(op, total)?;
        len_of(op, parts.len())?;
        let mut flat = Zeroizing::new(Vec::with_capacity(total));
        let mut sizes = Vec::with_capacity(parts.len());
        for p in parts {
            flat.extend_from_slice(p);
            sizes.push(p.len() as c_int);
        }
        Ok(Self { flat, sizes })
    }

    /// Valid while `self` lives; the library only reads it.
    pub(crate) fn raw(&mut self) -> cmems_t {
        cmems_t { count: self.sizes.len() as c_int, data: self.flat.as_mut_ptr(), sizes: self.sizes.as_mut_ptr() }
    }
}

/// Takes ownership of a library-allocated buffer: copy, wipe the C copy, free it.
///
/// # Safety
/// `m` must be a buffer returned by the library (malloc'ed, `size` bytes) or `{NULL, 0}`.
pub(crate) unsafe fn take_cmem(m: cmem_t) -> Zeroizing<Vec<u8>> {
    if m.data.is_null() {
        return Zeroizing::new(Vec::new());
    }
    let n = m.size.max(0) as usize;
    let slice = std::slice::from_raw_parts_mut(m.data, n);
    let out = Zeroizing::new(slice.to_vec());
    slice.zeroize();
    libc::free(m.data.cast());
    out
}

/// Takes ownership of a library-allocated list (`data` and `sizes` are separate allocations).
///
/// # Safety
/// `m` must be a list returned by the library or `{0, NULL, NULL}`.
pub(crate) unsafe fn take_cmems(m: cmems_t) -> Vec<Zeroizing<Vec<u8>>> {
    let count = m.count.max(0) as usize;
    let sizes: &[c_int] = if m.sizes.is_null() { &[] } else { std::slice::from_raw_parts(m.sizes, count) };
    let total: usize = sizes.iter().map(|s| (*s).max(0) as usize).sum();
    let mut out = Vec::with_capacity(sizes.len());
    if !m.data.is_null() {
        let flat = std::slice::from_raw_parts_mut(m.data, total);
        let mut off = 0;
        for s in sizes {
            let n = (*s).max(0) as usize;
            out.push(Zeroizing::new(flat[off..off + n].to_vec()));
            off += n;
        }
        flat.zeroize();
    } else {
        out.extend(sizes.iter().map(|_| Zeroizing::new(Vec::new())));
    }
    libc::free(m.data.cast());
    libc::free(m.sizes.cast());
    out
}

/// Copies `bytes` into a malloc'ed buffer the library takes over (receive callbacks). The library
/// wipes and frees it. Returns `{NULL, 0}` for empty input or when malloc fails (`ok == false`).
pub(crate) fn malloc_copy(bytes: &[u8]) -> (cmem_t, bool) {
    if bytes.is_empty() {
        return (cmem_t { data: std::ptr::null_mut(), size: 0 }, true);
    }
    let Ok(size) = c_int::try_from(bytes.len()) else { return (cmem_t { data: std::ptr::null_mut(), size: 0 }, false) };
    // SAFETY: fresh allocation of exactly `bytes.len()` bytes, filled before it is handed out.
    unsafe {
        let p = libc::malloc(bytes.len()) as *mut u8;
        if p.is_null() {
            return (cmem_t { data: p, size: 0 }, false);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        (cmem_t { data: p, size }, true)
    }
}
