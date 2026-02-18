//! Flutter Rust Bridge for KhodPay Wallet
//!
//! This crate provides Flutter bindings for the KhodPay wallet functionality.
//! 
//! ## Features
//! 
//! - **Object-Oriented API**: Full access to Rust structs with all their methods
//! - **Utility Functions**: Simple procedural functions for quick operations
//! - **BIP32/BIP39/BIP44 Support**: Complete HD wallet functionality
//! - **Multi-Coin Support**: Bitcoin, Ethereum, Litecoin, and more
//! - **Type Safety**: Strong typing on the Flutter/Dart side
//! 
//! ## Usage
//! 
//! This library exposes both OOP and procedural APIs to Flutter:
//! 
//! - `Mnemonic` - Mnemonic generation and management
//! - `ExtendedPrivateKey` - Private key operations
//! - `ExtendedPublicKey` - Public key operations
//! - `Bip44Wallet` - BIP44 multi-account wallet
//! - `Bip44Account` - BIP44 account for address derivation
//! - Utility functions like `generate_mnemonic()`, `create_bip44_account()`, etc.

// Include the bridge module with our API definitions
pub mod bridge;

// Include the generated FFI code (must be public for FFI symbols to be exported)
pub mod bridge_generated;

// Re-export everything from bridge module for public API
pub use bridge::*;
