use std::fmt;

/// A failed cb-mpc call: the operation and the library's error code (cb-mpc `error_t`, negative,
/// or a transport code). Never carries key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub op: &'static str,
    pub code: i32,
}

/// The code used when a Rust transport callback panicked (the panic is caught at the FFI boundary).
pub const TRANSPORT_PANIC: i32 = -0x7000_0001;
/// The code used when an input is too large for the C ABI's `int` sizes.
pub const TOO_LARGE: i32 = -0x7000_0002;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cb-mpc {} failed (code {} / {:#x})", self.op, self.code, self.code as u32)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn check(op: &'static str, rv: i32) -> Result<()> {
    if rv == 0 {
        Ok(())
    } else {
        Err(Error { op, code: rv })
    }
}

/// Clears the thread's "last error" so a value-returning call can be checked afterwards.
pub(crate) fn clear_last_error() {
    // SAFETY: plain thread-local read-and-reset in the library.
    unsafe { cbmpc_sys::cbmpc_ts_take_last_error() };
}

/// Error recorded by the last value-returning call on this thread (curve/point/key getters).
pub(crate) fn last_error(op: &'static str) -> Result<()> {
    // SAFETY: as above.
    check(op, unsafe { cbmpc_sys::cbmpc_ts_take_last_error() })
}
