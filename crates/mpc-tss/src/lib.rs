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
//! ## Usage
//!
//! ```
//! use khodpay_mpc_tss::{DeviceShare, MpcError, MpcSession, SessionState};
//!
//! // Construct a share from stored bytes.
//! let bytes: &[u8] = &[0x01, 0x02, 0x03];
//! let share = DeviceShare::from_bytes(bytes)?;
//! assert_eq!(share.to_bytes(), bytes);
//!
//! // Create a session and drive it through a round.
//! let mut session = MpcSession::new();
//! assert!(matches!(session.state(), SessionState::Pending));
//! session.advance_round(1)?;
//! assert!(matches!(session.state(), SessionState::InProgress { round: 1 }));
//! # Ok::<(), MpcError>(())
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![deny(unsafe_code)]

pub mod address;
mod dkg;
mod error;
mod resharing;
mod session;
mod share;
mod signing;

// Expose submodules publicly when the `test-utils` feature is active so that
// integration tests in other crates (e.g. `crates/flutter_bridge`) can reach
// the in-process ceremony helpers (`run_local`, `run_two_party_*`).
/// Re-exports of signing ceremony helpers for use in external integration tests.
///
/// Only available with the `test-utils` feature — never enable in production.
#[cfg(feature = "test-utils")]
pub mod signing_test_utils {
    pub use super::signing::*;
}
/// Re-exports of resharing ceremony helpers for use in external integration tests.
///
/// Only available with the `test-utils` feature — never enable in production.
#[cfg(feature = "test-utils")]
pub mod resharing_test_utils {
    pub use super::resharing::*;
}
/// Re-exports of DKG ceremony helpers for use in external integration tests.
///
/// Only available with the `test-utils` feature — never enable in production.
#[cfg(feature = "test-utils")]
pub mod dkg_test_utils {
    pub use super::dkg::*;
}

pub use dkg::{DkgOutput, DkgSession};
pub use error::{MpcError, Result};
pub use resharing::{ReshareOutput, ReshareSession};
pub use session::{MpcSession, RoundPayload, SessionState};
pub use share::DeviceShare;
pub use signing::{verify_signature_recovers_address, SigningOutput, SigningSession};
