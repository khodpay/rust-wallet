//! # Khodpay Signing
//!
//! EVM transaction signing library for BSC (BNB Smart Chain) and other EVM-compatible chains.
//!
//! This crate provides EIP-1559 (Type 2) transaction signing, integrating with
//! `khodpay-bip44` for HD wallet key derivation.
//!
//! ## Features
//!
//! - **EIP-1559 Transactions**: Modern fee market transactions
//! - **BSC Support**: Native support for BNB Smart Chain (mainnet/testnet)
//! - **BIP-44 Integration**: Seamless key derivation from HD wallets
//! - **BEP-20 Helpers**: Token transfer encoding utilities
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use khodpay_signing::{Eip1559Transaction, ChainId, Wei, Bip44Signer};
//! use khodpay_bip44::{Wallet, Purpose, CoinType, Language};
//! use khodpay_bip32::Network;
//!
//! // Create wallet and get account
//! let mnemonic = "your twelve word mnemonic phrase here";
//! let mut wallet = Wallet::from_mnemonic(mnemonic, "", Language::English, Network::BitcoinMainnet)?;
//! let account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0)?;
//!
//! // Create signer
//! let signer = Bip44Signer::new(account, 0)?;
//!
//! // Build transaction
//! let tx = Eip1559Transaction::builder()
//!     .chain_id(ChainId::BscMainnet)
//!     .nonce(0)
//!     .to("0x...".parse()?)
//!     .value(Wei::from_ether(1))
//!     .gas_limit(21000)
//!     .max_fee_per_gas(Wei::from_gwei(5))
//!     .max_priority_fee_per_gas(Wei::from_gwei(1))
//!     .build()?;
//!
//! // Sign and get raw transaction
//! let signed = signer.sign_transaction(&tx)?;
//! let raw_tx = signed.to_raw_transaction();
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![deny(unsafe_code)]

mod chain_id;
mod error;

pub use chain_id::ChainId;
pub use error::Error;

/// Result type alias for signing operations.
pub type Result<T> = std::result::Result<T, Error>;
