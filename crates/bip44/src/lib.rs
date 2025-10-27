//! # BIP-44: Multi-Account Hierarchy for Deterministic Wallets
//!
//! This crate provides a Rust implementation of [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki),
//! which defines a logical hierarchy for deterministic wallets based on BIP-32.
//!
//! ## BIP-44 Path Structure
//!
//! ```text
//! m / purpose' / coin_type' / account' / change / address_index
//! ```
//!
//! - **purpose'**: Constant set to 44' (or 49', 84', 86' for other standards)
//! - **coin_type'**: Cryptocurrency type (0' for Bitcoin, 60' for Ethereum, etc.)
//! - **account'**: Account index (allows multiple accounts per coin)
//! - **change**: 0 for external (receiving), 1 for internal (change)
//! - **address_index**: Address index within the chain

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![deny(unsafe_code)]

mod account;
mod error;
mod path;
mod types;

pub use account::Account;
pub use error::Error;
pub use path::{Bip44Path, Bip44PathBuilder};
pub use types::{Chain, CoinType, Purpose};

/// Result type alias for BIP-44 operations.
pub type Result<T> = std::result::Result<T, Error>;
