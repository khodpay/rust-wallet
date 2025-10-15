//! # BIP32 - Hierarchical Deterministic Wallets
//!
//! A production-ready Rust implementation of the BIP32 standard for hierarchical deterministic
//! wallets in cryptocurrency applications.
//!
//! ## Overview
//!
//! BIP32 (Bitcoin Improvement Proposal 32) defines the standard for creating hierarchical
//! deterministic (HD) wallets. This allows generating a tree of key pairs from a single seed,
//! enabling backup and recovery of unlimited keys using just the initial seed.
//!
//! ## Features
//!
//! - **Full BIP32 Compliance** - Implements the complete BIP32 specification
//! - **Type-Safe API** - Leverages Rust's type system for safety
//! - **BIP39 Integration** - Seamlessly works with BIP39 mnemonics
//! - **Hardened & Normal Derivation** - Supports both derivation types
//! - **Network Support** - Bitcoin mainnet and testnet
//! - **Zero Unsafe Code** - Pure safe Rust implementation
//! - **Production Ready** - Validated against official test vectors
//! - **Cross-Compatible** - Interoperable with major wallet implementations
//!
//! ## Quick Start
//!
//! ### Basic Usage
//!
//! ```rust
//! use bip32::{ExtendedPrivateKey, Network, DerivationPath};
//! use bip39::{Mnemonic, WordCount, Language};
//! use std::str::FromStr;
//!
//! // Generate a mnemonic (using BIP39)
//! let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;
//!
//! // Create master extended private key directly from mnemonic
//! let master_key = ExtendedPrivateKey::from_mnemonic(
//!     &mnemonic,
//!     None,  // Optional passphrase
//!     Network::BitcoinMainnet
//! )?;
//!
//! // Derive child keys using a BIP-44 path
//! let path = DerivationPath::from_str("m/44'/0'/0'")?;
//! let account_key = master_key.derive_path(&path)?;
//!
//! assert_eq!(account_key.depth(), 3);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ### Derive from Seed
//!
//! ```rust
//! use bip32::{ExtendedPrivateKey, Network};
//!
//! // Use a seed directly (typically from BIP39)
//! let seed = b"your-secure-seed-bytes-here-at-least-16-bytes-long";
//! let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet)?;
//!
//! // Get the extended public key
//! let master_pub = master.to_extended_public_key();
//! println!("Master xpub: {}", master_pub);
//! # Ok::<(), bip32::Error>(())
//! ```
//!
//! ### Watch-Only Wallets (Public Key Derivation)
//!
//! ```rust
//! use bip32::{ExtendedPrivateKey, Network, DerivationPath, ChildNumber};
//! use std::str::FromStr;
//!
//! # let seed = b"your-secure-seed-bytes-here-at-least-16-bytes-long";
//! # let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet)?;
//! // Derive account-level key (with hardened derivation)
//! let account_path = DerivationPath::from_str("m/44'/0'/0'")?;
//! let account_key = master.derive_path(&account_path)?;
//!
//! // Get the extended public key for watch-only wallet
//! let account_pub = account_key.to_extended_public_key();
//!
//! // Now derive receive addresses from public key only (no hardened)
//! let first_address = account_pub.derive_child(ChildNumber::Normal(0))?;
//! println!("First receive address xpub: {}", first_address);
//! # Ok::<(), bip32::Error>(())
//! ```
//!
//! ## Common Derivation Paths
//!
//! - **BIP44** - `m/44'/0'/0'` - Multi-account hierarchy for Bitcoin
//! - **BIP49** - `m/49'/0'/0'` - SegWit (P2WPKH-nested-in-P2SH)
//! - **BIP84** - `m/84'/0'/0'` - Native SegWit (P2WPKH)
//!
//! ## Security Considerations
//!
//! - Always use cryptographically secure random seeds
//! - Protect private keys and seeds with appropriate security measures
//! - Use hardened derivation (`'` or `H`) for account-level keys
//! - Never expose private keys or seeds over insecure channels
//! - The library uses `zeroize` to securely clear sensitive data from memory
//!
//! ## Compatibility
//!
//! This implementation is fully compatible with:
//! - Hardware wallets (Trezor, Ledger)
//! - Software wallets (Electrum, Bitcoin Core)
//! - All BIP32/44/49/84 compliant implementations

// Module declarations
mod chain_code;
mod child_number;
mod derivation_path;
mod error;
mod extended_private_key;
mod extended_public_key;
mod network;
mod private_key;
mod public_key;

/// Utility functions and convenience methods for common BIP32 operations.
///
/// This module provides ergonomic wrappers around common patterns to reduce
/// boilerplate in application code.
pub mod utils;

// Public re-exports
pub use chain_code::ChainCode;
pub use child_number::ChildNumber;
pub use derivation_path::DerivationPath;
pub use error::{Error, Result};
pub use extended_private_key::ExtendedPrivateKey;
pub use extended_public_key::ExtendedPublicKey;
pub use network::{KeyType, Network};
pub use private_key::PrivateKey;
pub use public_key::PublicKey;
