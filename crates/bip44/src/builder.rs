//! Builder pattern for fluent wallet construction.
//!
//! This module provides a builder pattern for creating wallets with a fluent API.
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip44::WalletBuilder;
//! use khodpay_bip32::Network;
//! use khodpay_bip39::Language;
//!
//! // Build from mnemonic
//! let wallet = WalletBuilder::new()
//!     .mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
//!     .language(Language::English)
//!     .network(Network::BitcoinMainnet)
//!     .build()
//!     .unwrap();
//! ```

use crate::{Error, Result, Wallet};
use khodpay_bip32::Network;
use khodpay_bip39::Language;

/// Builder for constructing a `Wallet` with a fluent API.
///
/// This builder provides a convenient way to construct wallets with various
/// configuration options in a type-safe manner.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::WalletBuilder;
/// use khodpay_bip32::Network;
/// use khodpay_bip39::Language;
///
/// // From mnemonic
/// let wallet = WalletBuilder::new()
///     .mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
///     .network(Network::BitcoinMainnet)
///     .build()
///     .unwrap();
///
/// // From seed
/// let seed = [0u8; 64];
/// let wallet = WalletBuilder::new()
///     .seed(&seed)
///     .network(Network::BitcoinTestnet)
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct WalletBuilder {
    mnemonic: Option<String>,
    seed: Option<Vec<u8>>,
    password: String,
    language: Language,
    network: Option<Network>,
}

impl WalletBuilder {
    /// Creates a new `WalletBuilder` with default settings.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::WalletBuilder;
    ///
    /// let builder = WalletBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            mnemonic: None,
            seed: None,
            password: String::new(),
            language: Language::English,
            network: None,
        }
    }

    /// Sets the BIP39 mnemonic phrase.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::WalletBuilder;
    ///
    /// let builder = WalletBuilder::new()
    ///     .mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    /// ```
    pub fn mnemonic(mut self, mnemonic: &str) -> Self {
        self.mnemonic = Some(mnemonic.to_string());
        self
    }

    /// Sets the raw seed bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::WalletBuilder;
    ///
    /// let seed = [0u8; 64];
    /// let builder = WalletBuilder::new().seed(&seed);
    /// ```
    pub fn seed(mut self, seed: &[u8]) -> Self {
        self.seed = Some(seed.to_vec());
        self
    }

    /// Sets the password for mnemonic-based wallet creation.
    ///
    /// This is optional and defaults to an empty string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::WalletBuilder;
    ///
    /// let builder = WalletBuilder::new()
    ///     .mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    ///     .password("my-secure-password");
    /// ```
    pub fn password(mut self, password: &str) -> Self {
        self.password = password.to_string();
        self
    }

    /// Sets the language for the mnemonic phrase.
    ///
    /// Defaults to English.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::WalletBuilder;
    /// use khodpay_bip39::Language;
    ///
    /// let builder = WalletBuilder::new()
    ///     .mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    ///     .language(Language::English);
    /// ```
    pub fn language(mut self, language: Language) -> Self {
        self.language = language;
        self
    }

    /// Sets the network for the wallet.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::WalletBuilder;
    /// use khodpay_bip32::Network;
    ///
    /// let builder = WalletBuilder::new()
    ///     .network(Network::BitcoinMainnet);
    /// ```
    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// Builds the wallet with the configured options.
    ///
    /// # Returns
    ///
    /// A `Wallet` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Neither mnemonic nor seed is provided
    /// - Network is not specified
    /// - Mnemonic is invalid
    /// - Seed is invalid
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::WalletBuilder;
    /// use khodpay_bip32::Network;
    ///
    /// let wallet = WalletBuilder::new()
    ///     .mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    ///     .network(Network::BitcoinMainnet)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn build(self) -> Result<Wallet> {
        // Validate network is set
        let network = self.network.ok_or_else(|| {
            Error::InvalidSeed("Network must be specified".to_string())
        })?;

        // Build from mnemonic or seed
        if let Some(mnemonic) = self.mnemonic {
            Wallet::from_mnemonic(&mnemonic, &self.password, self.language, network)
        } else if let Some(seed) = self.seed {
            Wallet::from_seed(&seed, network)
        } else {
            Err(Error::InvalidSeed(
                "Either mnemonic or seed must be provided".to_string(),
            ))
        }
    }
}

impl Default for WalletBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        let wallet = WalletBuilder::new()
            .mnemonic(mnemonic)
            .network(Network::BitcoinMainnet)
            .build()
            .unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_builder_from_seed() {
        let seed = [0u8; 64];
        
        let wallet = WalletBuilder::new()
            .seed(&seed)
            .network(Network::BitcoinMainnet)
            .build()
            .unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_builder_with_password() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        let wallet = WalletBuilder::new()
            .mnemonic(mnemonic)
            .password("my-password")
            .network(Network::BitcoinMainnet)
            .build()
            .unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_builder_with_language() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        let wallet = WalletBuilder::new()
            .mnemonic(mnemonic)
            .language(Language::English)
            .network(Network::BitcoinMainnet)
            .build()
            .unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_builder_testnet() {
        let seed = [0u8; 64];
        
        let wallet = WalletBuilder::new()
            .seed(&seed)
            .network(Network::BitcoinTestnet)
            .build()
            .unwrap();

        assert_eq!(wallet.network(), Network::BitcoinTestnet);
    }

    #[test]
    fn test_builder_no_network_error() {
        let seed = [0u8; 64];
        
        let result = WalletBuilder::new()
            .seed(&seed)
            .build();

        assert!(result.is_err());
        match result {
            Err(Error::InvalidSeed(msg)) => {
                assert!(msg.contains("Network must be specified"));
            }
            _ => panic!("Expected InvalidSeed error"),
        }
    }

    #[test]
    fn test_builder_no_source_error() {
        let result = WalletBuilder::new()
            .network(Network::BitcoinMainnet)
            .build();

        assert!(result.is_err());
        match result {
            Err(Error::InvalidSeed(msg)) => {
                assert!(msg.contains("Either mnemonic or seed must be provided"));
            }
            _ => panic!("Expected InvalidSeed error"),
        }
    }

    #[test]
    fn test_builder_fluent_api() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        let wallet = WalletBuilder::new()
            .mnemonic(mnemonic)
            .password("")
            .language(Language::English)
            .network(Network::BitcoinMainnet)
            .build()
            .unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_builder_default() {
        let builder = WalletBuilder::default();
        
        // Should have default values
        assert_eq!(builder.password, "");
        assert!(matches!(builder.language, Language::English));
    }

    #[test]
    fn test_builder_clone() {
        let builder1 = WalletBuilder::new()
            .mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
            .network(Network::BitcoinMainnet);

        let builder2 = builder1.clone();
        
        let wallet1 = builder1.build().unwrap();
        let wallet2 = builder2.build().unwrap();

        assert_eq!(wallet1.network(), wallet2.network());
    }

    #[test]
    fn test_builder_multiple_builds() {
        let seed = [0u8; 64];
        
        let builder = WalletBuilder::new()
            .seed(&seed)
            .network(Network::BitcoinMainnet);

        // Clone and build multiple times
        let wallet1 = builder.clone().build().unwrap();
        let wallet2 = builder.clone().build().unwrap();

        assert_eq!(wallet1.network(), wallet2.network());
    }

    #[test]
    fn test_builder_override_values() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Override network
        let wallet = WalletBuilder::new()
            .mnemonic(mnemonic)
            .network(Network::BitcoinTestnet)
            .network(Network::BitcoinMainnet) // Override
            .build()
            .unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_builder_invalid_mnemonic() {
        let result = WalletBuilder::new()
            .mnemonic("invalid mnemonic phrase")
            .network(Network::BitcoinMainnet)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_empty_seed() {
        let result = WalletBuilder::new()
            .seed(&[])
            .network(Network::BitcoinMainnet)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_24_word_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        
        let wallet = WalletBuilder::new()
            .mnemonic(mnemonic)
            .network(Network::BitcoinMainnet)
            .build()
            .unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
    }
}
