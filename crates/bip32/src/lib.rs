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
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use bip32::{ExtendedPrivateKey, DerivationPath};
//! use bip39::{Mnemonic, WordCount, Language};
//!
//! // Generate a mnemonic (using BIP39)
//! let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;
//!
//! // Convert mnemonic to seed
//! let seed = mnemonic.to_seed("")?;
//!
//! // Create master extended private key
//! let master_key = ExtendedPrivateKey::from_seed(&seed)?;
//!
//! // Derive child keys using a path
//! let path: DerivationPath = "m/0'/0'/0'".parse()?;
//! let child_key = master_key.derive_path(&path)?;
//! ```

// Module declarations
mod chain_code;
mod error;
mod extended_private_key;
mod extended_public_key;
mod network;
mod private_key;
mod public_key;

// Public re-exports
pub use chain_code::ChainCode;
pub use error::{Error, Result};
pub use extended_private_key::ExtendedPrivateKey;
pub use extended_public_key::ExtendedPublicKey;
pub use network::{KeyType, Network};
pub use private_key::PrivateKey;
pub use public_key::PublicKey;
