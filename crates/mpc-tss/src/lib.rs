//! # khodpay-mpc-tss
//!
//! 2-of-2 threshold ECDSA (CGGMP21) engine for secp256k1 / EVM — device side.
//!
//! This crate implements the cryptographic primitives required by the
//! KhodPay MPC wallet:
//!
//! | Operation | Entry point (future tasks) |
//! |---|---|
//! | Key generation (DKG) | `DkgSession` (Task 03) |
//! | Threshold signing | `SigningSession` (Task 04) |
//! | Share resharing | `ReshareSession` (Task 05) |
//!
//! ## Protocol
//!
//! The crate is backed by the **CGGMP21** protocol implemented by
//! [`cggmp21`](https://crates.io/crates/cggmp21) v0.6.3 on the
//! `secp256k1` curve.  No single complete private key is ever assembled
//! on either party at any point.
//!
//! ## Security
//!
//! All types that hold secret key material implement [`zeroize::Zeroize`]
//! and [`zeroize::ZeroizeOnDrop`].  `Debug` impls for such types output
//! `[REDACTED]` — bytes are never written to logs at any log level.
//!
//! ## Usage (scaffold — Task 01)
//!
//! Right now only the foundation types are available:
//!
//! ```
//! use khodpay_mpc_tss::{DeviceShare, MpcError};
//!
//! // Construct a share from stored bytes.
//! let bytes: &[u8] = &[/* ... secure-storage bytes ... */
//!     0x01, 0x02, 0x03];
//! let share = DeviceShare::from_bytes(bytes)?;
//! assert_eq!(share.to_bytes(), bytes);
//! # Ok::<(), MpcError>(())
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![deny(unsafe_code)]

mod error;
mod share;

pub use error::{MpcError, Result};
pub use share::DeviceShare;
