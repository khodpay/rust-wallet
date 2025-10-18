//! Flutter Rust Bridge for KhodPay Wallet
//!
//! This crate provides Flutter bindings for the KhodPay wallet functionality.
//! 
//! ## Features
//! 
//! - **Object-Oriented API**: Full access to Rust structs with all their methods
//! - **Utility Functions**: Simple procedural functions for quick operations
//! - **BIP32/BIP39 Support**: Complete HD wallet functionality
//! - **Type Safety**: Strong typing on the Flutter/Dart side
//! 
//! ## Usage
//! 
//! This library exposes both OOP and procedural APIs to Flutter:
//! 
//! - `Mnemonic` - Mnemonic generation and management
//! - `ExtendedPrivateKey` - Private key operations
//! - `ExtendedPublicKey` - Public key operations
//! - Utility functions like `generate_mnemonic()`, `create_master_key()`, etc.

// Include the bridge module with our API definitions
pub mod bridge;

// Re-export everything from bridge module for public API
pub use bridge::*;
