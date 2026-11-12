//! # khodpay-mpc-tss
//!
//! 2-of-3 threshold ECDSA (CGGMP21) for secp256k1 / EVM wallets.
//!
//! A wallet key is split into three shares and any two can sign:
//!
//! | Party | Share | Held by |
//! |---|---|---|
//! | 0 | device share | the user's device, for everyday signing |
//! | 1 | server share | the KhodPay signer server |
//! | 2 | recovery share | the user, encrypted with a passphrase and stored in their cloud drive |
//!
//! Everyday signing is parties 0 and 1. After the device is lost, parties 2
//! and 1 sign. With the server unavailable, parties 0 and 2 can sign on one
//! device. No complete private key is ever assembled in any of these cases.
//!
//! ## Modules
//!
//! | Module | Purpose |
//! |---|---|
//! | [`transport`] | Runs one party of a ceremony on a worker thread and moves its messages in batches, one batch per network round trip |
//! | [`dkg_flow`] | Key generation followed by aux-info generation. [`dkg_flow::DkgParty`] is one party; [`dkg_flow::DeviceDkg`] is the device side, which runs parties 0 and 2 together |
//! | [`aux_info`] | Aux-info generation, finished key shares, signing for a chosen pair of parties, and (de)serialisation of shares |
//! | [`signing`] helpers | Encode a signature as 65-byte `r ‖ s ‖ v` and check it against a wallet address |
//! | [`address`] | EVM address from the joint public key |
//!
//! ## Protocol
//!
//! The crate is backed by [`cggmp21`](https://crates.io/crates/cggmp21) 0.6.3
//! on the `secp256k1` curve, in its threshold mode. Key generation needs all
//! three parties online at once. That is why the device runs the recovery
//! party itself and hands the finished recovery share to the caller to
//! encrypt.
//!
//! ## Security
//!
//! * The byte form of a share ([`DeviceShare`]) is zeroized when dropped. The
//!   decoded `cggmp21` key share objects are **not** guaranteed to be wiped:
//!   that library does not implement `Zeroize` for them. They live only on the
//!   worker threads and in `DeviceDkg`, and are dropped, not scrubbed.
//!   Types that hold key material print nothing in `Debug`.
//! * While key generation runs, the device process holds two of the three
//!   shares and could sign alone. Encrypt the recovery share and drop it as
//!   soon as the ceremony returns it.
//! * A removed device keeps a usable copy of its share. The server stops
//!   signing for it, but the device share together with the recovery share
//!   still signs without the server.
//!
//! ## Usage
//!
//! ```
//! use khodpay_mpc_tss::{DeviceShare, MpcError};
//!
//! // Shares are opaque bytes while stored.
//! let bytes: &[u8] = &[0x01, 0x02, 0x03];
//! let share = DeviceShare::from_bytes(bytes)?;
//! assert_eq!(share.to_bytes(), bytes);
//! # Ok::<(), MpcError>(())
//! ```
#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![deny(unsafe_code)]

pub mod address;
pub mod aux_info;
pub mod dkg_flow;
mod error;
mod share;
mod signing;
pub mod transport;

pub use error::{MpcError, Result};
pub use share::DeviceShare;
pub use signing::{encode_signature_evm, verify_signature_recovers_address};
