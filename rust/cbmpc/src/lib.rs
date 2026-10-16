//! Safe Rust API for cb-mpc's 2-party ECDSA and EdDSA (Schnorr-2P), over the cb-mpc-ts C ABI.
//!
//! Keys serialize to the same parts as cb-mpc-ts `serializeEcdsa2p` / `serializeEcKey2p` and the
//! protocols exchange the same messages, so a Rust party interoperates with the TypeScript package
//! (WASM or native) and with shares stored by it.
//!
//! - Handles are RAII: keys, curves, points and jobs are freed on drop.
//! - Secret bytes (serialized parts, x shares, PVE decryption keys) come back as `Zeroizing`
//!   buffers, and the library's own copies are wiped before they are freed.
//! - A protocol call blocks on its `Transport`: run each session on its own thread.
//! - `cbmpc-sys` links its own static OpenSSL 3.6.4 (libcrypto). Do not combine it with
//!   `openssl-sys` in the same binary (use rustls for TLS); two libcrypto copies would mix symbols.
//!
//! ```no_run
//! use cbmpc::{Ecdsa2pKey, Job2p, Party, NID_SECP256K1};
//! # fn run(transport: &mut dyn cbmpc::Transport) -> cbmpc::Result<()> {
//! let mut job = Job2p::new(transport, Party::P2, ["client", "server"])?;
//! let key = Ecdsa2pKey::dkg(&mut job, NID_SECP256K1)?;
//! let parts = key.serialize()?; // store these (encrypted)
//! # Ok(()) }
//! ```

mod curve;
mod ecdsa2p;
mod eckey2p;
mod error;
mod mem;
pub mod pve;
mod transport;

pub use curve::{verify_der, Curve, Point, NID_ED25519, NID_SECP256K1, NID_X9_62_PRIME256V1};
pub use ecdsa2p::Ecdsa2pKey;
pub use eckey2p::EcKey2p;
pub use error::{Error, Result, ROLE_MISMATCH, TOO_LARGE, TRANSPORT_PANIC};
pub use transport::{Job2p, Party, Transport, TransportError};
pub use zeroize::Zeroizing;
