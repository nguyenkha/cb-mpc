// Blocking transport + 2-party job. cb-mpc calls the transport synchronously from inside a protocol
// call, so a protocol run owns its thread: `receive` blocks until the peer's message arrives (e.g. a
// channel fed by an HTTP handler) and returns an error to abort the run (timeout, cancel).
// Callbacks never let a Rust panic unwind into C++: it is caught and turned into a transport error.

use crate::error::{check, Error, Result, ROLE_MISMATCH, TRANSPORT_PANIC};
use crate::mem::malloc_copy;
use cbmpc_sys::{
    cmem_t, cmems_t, data_transport_callbacks_t, job_2p_ref, NETWORK_ERROR, NETWORK_MEMORY_ERROR,
};
use std::ffi::CString;
use std::os::raw::{c_int, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use zeroize::Zeroizing;

/// The transport failed or was closed; the protocol run fails with a network error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportError;

/// One party's view of the network. Party indices are 0 and 1 (`Party`).
pub trait Transport {
    /// Protocol messages can carry secret sub-shares: an implementation that buffers `message`
    /// should keep its copy in `Zeroizing`.
    fn send(&mut self, receiver: i32, message: &[u8]) -> std::result::Result<(), TransportError>;
    /// Blocks until the message from `sender` arrives. Messages may carry secret sub-shares; the
    /// returned buffer is copied into library memory and then dropped.
    fn receive(&mut self, sender: i32) -> std::result::Result<Zeroizing<Vec<u8>>, TransportError>;
}

/// The two roles of a 2-party protocol. kexify: P1 = client (index 0), P2 = server (index 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
    P1 = 0,
    P2 = 1,
}

struct Ctx<'a> {
    transport: &'a mut dyn Transport,
    panicked: bool,
}

/// Runs `f` on the callback context, mapping errors and panics to a C status code.
unsafe fn with_ctx(ctx: *mut c_void, f: impl FnOnce(&mut dyn Transport) -> c_int) -> c_int {
    let ctx = &mut *(ctx as *mut Ctx);
    match catch_unwind(AssertUnwindSafe(|| f(&mut *ctx.transport))) {
        Ok(rv) => rv,
        Err(_) => {
            ctx.panicked = true;
            NETWORK_ERROR
        }
    }
}

unsafe extern "C" fn send_cb(ctx: *mut c_void, receiver: c_int, msg: cmem_t) -> c_int {
    let bytes: &[u8] = if msg.data.is_null() || msg.size <= 0 {
        &[]
    } else {
        std::slice::from_raw_parts(msg.data, msg.size as usize)
    };
    with_ctx(ctx, |t| match t.send(receiver, bytes) {
        Ok(()) => 0,
        Err(_) => NETWORK_ERROR,
    })
}

unsafe extern "C" fn receive_cb(ctx: *mut c_void, sender: c_int, out: *mut cmem_t) -> c_int {
    *out = cmem_t {
        data: std::ptr::null_mut(),
        size: 0,
    };
    with_ctx(ctx, |t| match t.receive(sender) {
        Ok(msg) => {
            let (m, ok) = malloc_copy(&msg);
            *out = m;
            if ok {
                0
            } else {
                NETWORK_MEMORY_ERROR
            }
        }
        Err(_) => NETWORK_ERROR,
    })
}

unsafe extern "C" fn receive_all_cb(
    ctx: *mut c_void,
    senders: *mut c_int,
    n: c_int,
    out: *mut cmems_t,
) -> c_int {
    *out = cmems_t {
        count: 0,
        data: std::ptr::null_mut(),
        sizes: std::ptr::null_mut(),
    };
    let senders: &[c_int] = if senders.is_null() || n <= 0 {
        &[]
    } else {
        std::slice::from_raw_parts(senders, n as usize)
    };
    with_ctx(ctx, |t| {
        let mut msgs = Vec::with_capacity(senders.len());
        for s in senders {
            match t.receive(*s) {
                Ok(m) => msgs.push(m),
                Err(_) => return NETWORK_ERROR,
            }
        }
        let mut flat: Zeroizing<Vec<u8>> =
            Zeroizing::new(msgs.iter().flat_map(|m| m.iter().copied()).collect());
        if flat.is_empty() {
            flat.push(0); // never hand out NULL data: a 1-byte sentinel, sizes still say 0
        }
        let (data, ok) = malloc_copy(&flat);
        let sizes = libc::malloc(std::mem::size_of::<c_int>() * senders.len().max(1)) as *mut c_int;
        if !ok || sizes.is_null() {
            if !data.data.is_null() {
                // The copy may hold secret sub-shares: wipe before free.
                std::ptr::write_bytes(data.data, 0, data.size as usize);
            }
            libc::free(data.data.cast());
            libc::free(sizes.cast());
            return NETWORK_MEMORY_ERROR;
        }
        for (i, m) in msgs.iter().enumerate() {
            *sizes.add(i) = m.len() as c_int;
        }
        *out = cmems_t {
            count: senders.len() as c_int,
            data: data.data,
            sizes,
        };
        0
    })
}

static CALLBACKS: data_transport_callbacks_t = data_transport_callbacks_t {
    send_fun: Some(send_cb),
    receive_fun: Some(receive_cb),
    receive_all_fun: Some(receive_all_cb),
};

/// A 2-party job bound to one transport for its lifetime. Not `Send`: a run stays on its thread.
pub struct Job2p<'a> {
    raw: *mut job_2p_ref,
    /// From `Box::into_raw`; the library holds this pointer, so it is only turned back into a Box
    /// in Drop, after the job is freed.
    ctx: *mut Ctx<'a>,
    party: Party,
}

impl<'a> Job2p<'a> {
    /// `names` are the two parties' names in index order (kexify: `["client", "server"]`).
    pub fn new(transport: &'a mut dyn Transport, party: Party, names: [&str; 2]) -> Result<Self> {
        let err = Error {
            op: "new_job_2p",
            code: -1,
        };
        let c_names = [
            CString::new(names[0]).map_err(|_| err)?,
            CString::new(names[1]).map_err(|_| err)?,
        ];
        let ptrs = [c_names[0].as_ptr(), c_names[1].as_ptr()];
        let ctx = Box::into_raw(Box::new(Ctx {
            transport,
            panicked: false,
        }));
        // SAFETY: callbacks are 'static; ctx stays valid until Drop frees it after the job; the
        // library copies the names.
        let raw = unsafe {
            cbmpc_sys::new_job_2p(&CALLBACKS, ctx.cast(), party as c_int, ptrs.as_ptr(), 2)
        };
        if raw.is_null() {
            // SAFETY: the library did not keep ctx.
            drop(unsafe { Box::from_raw(ctx) });
            return Err(err);
        }
        Ok(Self { raw, ctx, party })
    }

    pub(crate) fn raw(&mut self) -> *mut job_2p_ref {
        self.raw
    }

    /// Refuses a key whose role is not this job's party (the protocol would only fail later).
    pub(crate) fn check_role(&self, op: &'static str, role_index: i32) -> Result<()> {
        if role_index == self.party as i32 {
            Ok(())
        } else {
            Err(Error {
                op,
                code: ROLE_MISMATCH,
            })
        }
    }

    /// The status of a protocol call, reporting a caught callback panic as such.
    pub(crate) fn finish(&mut self, op: &'static str, rv: c_int) -> Result<()> {
        // SAFETY: ctx is live for the job's lifetime and no callback runs outside a protocol call.
        if std::mem::take(unsafe { &mut (*self.ctx).panicked }) {
            return Err(Error {
                op,
                code: TRANSPORT_PANIC,
            });
        }
        check(op, rv)
    }
}

impl Drop for Job2p<'_> {
    fn drop(&mut self) {
        // SAFETY: raw came from new_job_2p and is freed once; then ctx (from Box::into_raw) once.
        unsafe {
            cbmpc_sys::free_job_2p(self.raw);
            drop(Box::from_raw(self.ctx));
        }
    }
}
