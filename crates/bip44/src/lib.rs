//! # BIP-44: Multi-Account Hierarchy for Deterministic Wallets
//!
//! This crate provides a production-ready Rust implementation of [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki),
//! which defines a logical hierarchy for deterministic wallets based on BIP-32.
//!
//! ## Features
//!
//! - **Multi-Account Support**: Manage multiple accounts per cryptocurrency
//! - **Multi-Coin Support**: Support for Bitcoin, Ethereum, Litecoin, and more
//! - **BIP Standards**: Support for BIP-44, BIP-49, BIP-84, and BIP-86
//! - **Account Caching**: Efficient account derivation with caching
//! - **Builder Pattern**: Fluent API for wallet construction
//! - **Serialization**: Optional serde support for persistence
//! - **Type Safety**: Strong typing for paths, chains, and coin types
//!
//! ## Quick Start
//!
//! ```rust
//! use khodpay_bip44::{Wallet, Purpose, CoinType, Language};
//! use khodpay_bip32::Network;
//!
//! // Create a wallet from a mnemonic
//! let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let mut wallet = Wallet::from_mnemonic(
//!     mnemonic,
//!     "",  // password
//!     Language::English,
//!     Network::BitcoinMainnet,
//! )?;
//!
//! // Get the first Bitcoin account
//! let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;
//!
//! // Derive receiving addresses
//! let addr0 = account.derive_external(0)?;
//! let addr1 = account.derive_external(1)?;
//!
//! // Derive change addresses
//! let change0 = account.derive_internal(0)?;
//! # Ok::<(), khodpay_bip44::Error>(())
//! ```
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
//!
//! ## Common Use Cases
//!
//! ### Creating a Multi-Coin Wallet
//!
//! ```rust
//! use khodpay_bip44::{Wallet, Purpose, CoinType, Language};
//! use khodpay_bip32::Network;
//!
//! let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet)?;
//!
//! // Bitcoin account
//! let btc_account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;
//! let btc_addr = btc_account.derive_external(0)?;
//!
//! // Ethereum account
//! let eth_account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0)?;
//! let eth_addr = eth_account.derive_external(0)?;
//! # Ok::<(), khodpay_bip44::Error>(())
//! ```
//!
//! ### Using the Builder Pattern
//!
//! ```rust
//! use khodpay_bip44::{WalletBuilder, Purpose, CoinType, Language};
//! use khodpay_bip32::Network;
//!
//! let mut wallet = WalletBuilder::new()
//!     .mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
//!     .password("my-secure-password")
//!     .language(Language::English)
//!     .network(Network::BitcoinMainnet)
//!     .build()?;
//!
//! let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;
//! # Ok::<(), khodpay_bip44::Error>(())
//! ```
//!
//! ### Batch Address Generation
//!
//! ```rust
//! use khodpay_bip44::{Wallet, Purpose, CoinType, Chain, Language};
//! use khodpay_bip32::Network;
//!
//! let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet)?;
//! let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;
//!
//! // Generate 20 receiving addresses
//! let addresses = account.derive_address_range(Chain::External, 0, 20)?;
//! assert_eq!(addresses.len(), 20);
//! # Ok::<(), khodpay_bip44::Error>(())
//! ```
//!
//! ### Using Path Strings
//!
//! ```rust
//! use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
//!
//! // Parse a BIP-44 path
//! let path: Bip44Path = "m/44'/0'/0'/0/0".parse()?;
//! assert_eq!(path.purpose(), Purpose::BIP44);
//! assert_eq!(path.coin_type(), CoinType::Bitcoin);
//! assert_eq!(path.account(), 0);
//! assert_eq!(path.chain(), Chain::External);
//! assert_eq!(path.address_index(), 0);
//!
//! // Convert back to string
//! assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
//! # Ok::<(), khodpay_bip44::Error>(())
//! ```
//!
//! ### SegWit and Taproot
//!
//! ```rust
//! use khodpay_bip44::{Wallet, Purpose, CoinType, Language};
//! use khodpay_bip32::Network;
//!
//! let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet)?;
//!
//! // BIP-84: Native SegWit (bc1q...)
//! let segwit_account = wallet.get_account(Purpose::BIP84, CoinType::Bitcoin, 0)?;
//!
//! // BIP-86: Taproot (bc1p...)
//! let taproot_account = wallet.get_account(Purpose::BIP86, CoinType::Bitcoin, 0)?;
//! # Ok::<(), khodpay_bip44::Error>(())
//! ```
//!
//! ## Security Considerations
//!
//! - **Mnemonic Storage**: Never store mnemonics in plain text. Use secure storage.
//! - **Password Protection**: Use strong passwords for additional security (BIP-39 passphrase).
//! - **Key Material**: Private keys should never leave secure memory.
//! - **Gap Limit**: Follow BIP-44 gap limit (20) for address discovery.
//!
//! ## Supported Cryptocurrencies
//!
//! This crate supports all SLIP-44 registered coin types, including:
//!
//! - Bitcoin (BTC) - Coin type 0
//! - Ethereum (ETH) - Coin type 60
//! - Litecoin (LTC) - Coin type 2
//! - Dogecoin (DOGE) - Coin type 3
//! - And many more via [`CoinType::Custom`]
//!
//! ## Optional Features
//!
//! - `serde`: Enable serialization support for paths and metadata

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![deny(unsafe_code)]

mod account;
mod builder;
mod derived;
mod discovery;
mod error;
mod iterator;
mod path;
mod types;
mod wallet;

pub use account::{Account, AccountMetadata};
pub use builder::WalletBuilder;
pub use derived::DerivedAddress;
pub use discovery::{
    AccountDiscovery, AccountScanResult, AccountScanner, ChainScanResult, GapLimitChecker,
    MockBlockchain, DEFAULT_GAP_LIMIT,
};
pub use error::Error;
pub use iterator::AddressIterator;
pub use path::{Bip44Path, Bip44PathBuilder};
pub use types::{Chain, CoinType, Purpose};
pub use wallet::Wallet;

// Re-export Language from BIP39 for convenience
pub use khodpay_bip39::Language;

/// Result type alias for BIP-44 operations.
pub type Result<T> = std::result::Result<T, Error>;
