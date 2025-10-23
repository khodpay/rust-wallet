//! BIP-44 path construction and manipulation.
//!
//! This module provides the core [`Bip44Path`] type for representing and working
//! with BIP-44 derivation paths.
//!
//! # BIP-44 Path Structure
//!
//! A complete BIP-44 path has exactly 5 levels:
//!
//! ```text
//! m / purpose' / coin_type' / account' / chain / address_index
//! ```
//!
//! - **purpose'**: Hardened. BIP standard (44, 49, 84, or 86)
//! - **coin_type'**: Hardened. Cryptocurrency type (SLIP-44)
//! - **account'**: Hardened. Account index
//! - **chain**: Normal. 0=external (receiving), 1=internal (change)
//! - **address_index**: Normal. Address index within the chain
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
//!
//! // Create a BIP-44 path for Bitcoin's first receiving address
//! let path = Bip44Path::new(
//!     Purpose::BIP44,
//!     CoinType::Bitcoin,
//!     0,
//!     Chain::External,
//!     0,
//! ).unwrap();
//!
//! // Path represents: m/44'/0'/0'/0/0
//! assert_eq!(path.purpose(), Purpose::BIP44);
//! assert_eq!(path.coin_type(), CoinType::Bitcoin);
//! assert_eq!(path.account(), 0);
//! assert_eq!(path.chain(), Chain::External);
//! assert_eq!(path.address_index(), 0);
//! ```

use crate::{Chain, CoinType, Error, Purpose, Result};
use khodpay_bip32::{ChildNumber, DerivationPath};

/// Maximum value for hardened derivation indices (2^31 - 1).
///
/// BIP-32 reserves the upper half of the u32 range for hardened derivation.
/// Hardened indices are [2^31, 2^32-1], normal indices are [0, 2^31-1].
pub const MAX_HARDENED_INDEX: u32 = 0x7FFF_FFFF;

/// BIP-44 derivation path.
///
/// Represents a complete BIP-44 path with all 5 levels:
/// `m / purpose' / coin_type' / account' / chain / address_index`
///
/// # Path Rules
///
/// - The first 3 levels (purpose, coin_type, account) MUST use hardened derivation
/// - The last 2 levels (chain, address_index) MUST use normal derivation
/// - Account index must be ≤ 2^31 - 1 (0x7FFFFFFF)
/// - Address index can be any u32 value
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
///
/// // Bitcoin receiving address
/// let btc_receive = Bip44Path::new(
///     Purpose::BIP84,
///     CoinType::Bitcoin,
///     0,
///     Chain::External,
///     0,
/// ).unwrap();
///
/// // Ethereum change address
/// let eth_change = Bip44Path::new(
///     Purpose::BIP44,
///     CoinType::Ethereum,
///     1,
///     Chain::Internal,
///     5,
/// ).unwrap();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bip44Path {
    purpose: Purpose,
    coin_type: CoinType,
    account: u32,
    chain: Chain,
    address_index: u32,
}

impl Bip44Path {
    /// Creates a new BIP-44 path with the specified components.
    ///
    /// # Arguments
    ///
    /// * `purpose` - The BIP standard (BIP-44, BIP-49, BIP-84, or BIP-86)
    /// * `coin_type` - The cryptocurrency type
    /// * `account` - The account index (must be ≤ 2^31 - 1)
    /// * `chain` - The chain type (external or internal)
    /// * `address_index` - The address index
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAccount`] if the account index exceeds 2^31 - 1.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// // Valid path
    /// let path = Bip44Path::new(
    ///     Purpose::BIP44,
    ///     CoinType::Bitcoin,
    ///     0,
    ///     Chain::External,
    ///     0,
    /// ).unwrap();
    ///
    /// // Account too large
    /// let result = Bip44Path::new(
    ///     Purpose::BIP44,
    ///     CoinType::Bitcoin,
    ///     0x8000_0000, // 2^31, too large
    ///     Chain::External,
    ///     0,
    /// );
    /// assert!(result.is_err());
    /// ```
    pub fn new(
        purpose: Purpose,
        coin_type: CoinType,
        account: u32,
        chain: Chain,
        address_index: u32,
    ) -> Result<Self> {
        // Validate account index is within hardened range
        if account > MAX_HARDENED_INDEX {
            return Err(Error::InvalidAccount {
                reason: format!(
                    "Account index {} exceeds maximum hardened index {}",
                    account, MAX_HARDENED_INDEX
                ),
            });
        }

        Ok(Self {
            purpose,
            coin_type,
            account,
            chain,
            address_index,
        })
    }

    /// Returns the purpose (BIP standard).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::new(Purpose::BIP84, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    /// assert_eq!(path.purpose(), Purpose::BIP84);
    /// ```
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// Returns the coin type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::new(Purpose::BIP44, CoinType::Ethereum, 0, Chain::External, 0).unwrap();
    /// assert_eq!(path.coin_type(), CoinType::Ethereum);
    /// ```
    pub const fn coin_type(&self) -> CoinType {
        self.coin_type
    }

    /// Returns the account index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 5, Chain::External, 0).unwrap();
    /// assert_eq!(path.account(), 5);
    /// ```
    pub const fn account(&self) -> u32 {
        self.account
    }

    /// Returns the chain type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::Internal, 0).unwrap();
    /// assert_eq!(path.chain(), Chain::Internal);
    /// ```
    pub const fn chain(&self) -> Chain {
        self.chain
    }

    /// Returns the address index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 42).unwrap();
    /// assert_eq!(path.address_index(), 42);
    /// ```
    pub const fn address_index(&self) -> u32 {
        self.address_index
    }

    /// Creates a new builder for constructing a BIP-44 path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::builder()
    ///     .purpose(Purpose::BIP44)
    ///     .coin_type(CoinType::Bitcoin)
    ///     .account(0)
    ///     .chain(Chain::External)
    ///     .address_index(0)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder() -> Bip44PathBuilder {
        Bip44PathBuilder::default()
    }

    /// Converts this BIP-44 path to a BIP-32 derivation path.
    ///
    /// The conversion follows BIP-44 rules:
    /// - First 3 levels (purpose, coin_type, account) use hardened derivation
    /// - Last 2 levels (chain, address_index) use normal derivation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    /// use khodpay_bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let bip44_path = Bip44Path::new(
    ///     Purpose::BIP44,
    ///     CoinType::Bitcoin,
    ///     0,
    ///     Chain::External,
    ///     0,
    /// ).unwrap();
    ///
    /// let derivation_path: DerivationPath = bip44_path.into();
    ///
    /// // This should equal "m/44'/0'/0'/0/0"
    /// let expected = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
    /// assert_eq!(derivation_path, expected);
    /// ```
    pub fn to_derivation_path(&self) -> DerivationPath {
        let child_numbers = vec![
            ChildNumber::Hardened(self.purpose.value()),
            ChildNumber::Hardened(self.coin_type.index()),
            ChildNumber::Hardened(self.account),
            ChildNumber::Normal(self.chain.value()),
            ChildNumber::Normal(self.address_index),
        ];

        DerivationPath::new(child_numbers)
    }
}

impl From<Bip44Path> for DerivationPath {
    /// Converts a BIP-44 path to a BIP-32 derivation path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    /// use khodpay_bip32::DerivationPath;
    ///
    /// let bip44_path = Bip44Path::new(
    ///     Purpose::BIP84,
    ///     CoinType::Ethereum,
    ///     5,
    ///     Chain::Internal,
    ///     100,
    /// ).unwrap();
    ///
    /// let derivation_path: DerivationPath = bip44_path.into();
    /// assert_eq!(derivation_path.depth(), 5);
    /// ```
    fn from(path: Bip44Path) -> Self {
        path.to_derivation_path()
    }
}

impl From<&Bip44Path> for DerivationPath {
    /// Converts a reference to a BIP-44 path to a BIP-32 derivation path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    /// use khodpay_bip32::DerivationPath;
    ///
    /// let bip44_path = Bip44Path::new(
    ///     Purpose::BIP44,
    ///     CoinType::Bitcoin,
    ///     0,
    ///     Chain::External,
    ///     0,
    /// ).unwrap();
    ///
    /// let derivation_path: DerivationPath = (&bip44_path).into();
    /// assert_eq!(derivation_path.depth(), 5);
    /// ```
    fn from(path: &Bip44Path) -> Self {
        path.to_derivation_path()
    }
}

/// Builder for constructing BIP-44 paths with a fluent API.
///
/// This builder provides a convenient way to construct [`Bip44Path`] instances
/// using method chaining. All fields must be set before calling [`build()`].
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
///
/// // Build a complete path
/// let path = Bip44Path::builder()
///     .purpose(Purpose::BIP84)
///     .coin_type(CoinType::Bitcoin)
///     .account(0)
///     .chain(Chain::External)
///     .address_index(5)
///     .build()
///     .unwrap();
///
/// assert_eq!(path.purpose(), Purpose::BIP84);
/// assert_eq!(path.address_index(), 5);
/// ```
///
/// [`build()`]: Bip44PathBuilder::build
#[derive(Debug, Default, Clone)]
pub struct Bip44PathBuilder {
    purpose: Option<Purpose>,
    coin_type: Option<CoinType>,
    account: Option<u32>,
    chain: Option<Chain>,
    address_index: Option<u32>,
}

impl Bip44PathBuilder {
    /// Creates a new empty builder.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Bip44Path;
    ///
    /// let builder = Bip44Path::builder();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the purpose (BIP standard).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose};
    ///
    /// let builder = Bip44Path::builder().purpose(Purpose::BIP84);
    /// ```
    pub fn purpose(mut self, purpose: Purpose) -> Self {
        self.purpose = Some(purpose);
        self
    }

    /// Sets the coin type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, CoinType};
    ///
    /// let builder = Bip44Path::builder().coin_type(CoinType::Ethereum);
    /// ```
    pub fn coin_type(mut self, coin_type: CoinType) -> Self {
        self.coin_type = Some(coin_type);
        self
    }

    /// Sets the account index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Bip44Path;
    ///
    /// let builder = Bip44Path::builder().account(5);
    /// ```
    pub fn account(mut self, account: u32) -> Self {
        self.account = Some(account);
        self
    }

    /// Sets the chain type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Chain};
    ///
    /// let builder = Bip44Path::builder().chain(Chain::Internal);
    /// ```
    pub fn chain(mut self, chain: Chain) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Sets the address index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Bip44Path;
    ///
    /// let builder = Bip44Path::builder().address_index(100);
    /// ```
    pub fn address_index(mut self, address_index: u32) -> Self {
        self.address_index = Some(address_index);
        self
    }

    /// Builds the BIP-44 path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPath`] if any required field is missing.
    /// Returns [`Error::InvalidAccount`] if the account index is invalid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// // Valid path
    /// let path = Bip44Path::builder()
    ///     .purpose(Purpose::BIP44)
    ///     .coin_type(CoinType::Bitcoin)
    ///     .account(0)
    ///     .chain(Chain::External)
    ///     .address_index(0)
    ///     .build()
    ///     .unwrap();
    ///
    /// // Missing field
    /// let result = Bip44Path::builder()
    ///     .purpose(Purpose::BIP44)
    ///     .build();
    /// assert!(result.is_err());
    /// ```
    pub fn build(self) -> Result<Bip44Path> {
        let purpose = self.purpose.ok_or_else(|| Error::InvalidPath {
            reason: "Purpose is required".to_string(),
        })?;

        let coin_type = self.coin_type.ok_or_else(|| Error::InvalidPath {
            reason: "Coin type is required".to_string(),
        })?;

        let account = self.account.ok_or_else(|| Error::InvalidPath {
            reason: "Account is required".to_string(),
        })?;

        let chain = self.chain.ok_or_else(|| Error::InvalidPath {
            reason: "Chain is required".to_string(),
        })?;

        let address_index = self.address_index.ok_or_else(|| Error::InvalidPath {
            reason: "Address index is required".to_string(),
        })?;

        Bip44Path::new(purpose, coin_type, account, chain, address_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_valid_path() {
        let path = Bip44Path::new(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Chain::External,
            0,
        )
        .unwrap();

        assert_eq!(path.purpose(), Purpose::BIP44);
        assert_eq!(path.coin_type(), CoinType::Bitcoin);
        assert_eq!(path.account(), 0);
        assert_eq!(path.chain(), Chain::External);
        assert_eq!(path.address_index(), 0);
    }

    #[test]
    fn test_new_with_different_purposes() {
        for purpose in [Purpose::BIP44, Purpose::BIP49, Purpose::BIP84, Purpose::BIP86] {
            let path = Bip44Path::new(purpose, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
            assert_eq!(path.purpose(), purpose);
        }
    }

    #[test]
    fn test_new_with_different_coins() {
        let btc = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(btc.coin_type(), CoinType::Bitcoin);

        let eth = Bip44Path::new(Purpose::BIP44, CoinType::Ethereum, 0, Chain::External, 0).unwrap();
        assert_eq!(eth.coin_type(), CoinType::Ethereum);

        let custom = Bip44Path::new(Purpose::BIP44, CoinType::Custom(999), 0, Chain::External, 0).unwrap();
        assert_eq!(custom.coin_type(), CoinType::Custom(999));
    }

    #[test]
    fn test_new_with_different_accounts() {
        let acc0 = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(acc0.account(), 0);

        let acc1 = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 1, Chain::External, 0).unwrap();
        assert_eq!(acc1.account(), 1);

        let acc_max = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, MAX_HARDENED_INDEX, Chain::External, 0).unwrap();
        assert_eq!(acc_max.account(), MAX_HARDENED_INDEX);
    }

    #[test]
    fn test_new_with_different_chains() {
        let external = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(external.chain(), Chain::External);

        let internal = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::Internal, 0).unwrap();
        assert_eq!(internal.chain(), Chain::Internal);
    }

    #[test]
    fn test_new_with_different_address_indices() {
        let addr0 = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(addr0.address_index(), 0);

        let addr100 = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 100).unwrap();
        assert_eq!(addr100.address_index(), 100);

        let addr_max = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, u32::MAX).unwrap();
        assert_eq!(addr_max.address_index(), u32::MAX);
    }

    #[test]
    fn test_new_account_too_large() {
        let result = Bip44Path::new(
            Purpose::BIP44,
            CoinType::Bitcoin,
            MAX_HARDENED_INDEX + 1,
            Chain::External,
            0,
        );
        assert!(result.is_err());
        
        let err = result.unwrap_err();
        assert!(matches!(err, Error::InvalidAccount { .. }));
    }

    #[test]
    fn test_new_account_at_boundary() {
        // MAX_HARDENED_INDEX should succeed
        let result = Bip44Path::new(
            Purpose::BIP44,
            CoinType::Bitcoin,
            MAX_HARDENED_INDEX,
            Chain::External,
            0,
        );
        assert!(result.is_ok());

        // MAX_HARDENED_INDEX + 1 should fail
        let result = Bip44Path::new(
            Purpose::BIP44,
            CoinType::Bitcoin,
            MAX_HARDENED_INDEX + 1,
            Chain::External,
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_path_equality() {
        let path1 = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let path2 = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let path3 = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 1, Chain::External, 0).unwrap();

        assert_eq!(path1, path2);
        assert_ne!(path1, path3);
    }

    #[test]
    fn test_path_clone() {
        let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let cloned = path;
        assert_eq!(path, cloned);
    }

    #[test]
    fn test_path_debug() {
        let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let debug = format!("{:?}", path);
        assert!(debug.contains("Bip44Path"));
    }

    #[test]
    fn test_realistic_paths() {
        // Bitcoin first receiving address: m/44'/0'/0'/0/0
        let btc_first = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(btc_first.purpose(), Purpose::BIP44);
        assert_eq!(btc_first.coin_type(), CoinType::Bitcoin);

        // Ethereum second account, fifth change address: m/44'/60'/1'/1/4
        let eth_change = Bip44Path::new(Purpose::BIP44, CoinType::Ethereum, 1, Chain::Internal, 4).unwrap();
        assert_eq!(eth_change.account(), 1);
        assert_eq!(eth_change.chain(), Chain::Internal);
        assert_eq!(eth_change.address_index(), 4);

        // Native SegWit Bitcoin: m/84'/0'/0'/0/0
        let btc_segwit = Bip44Path::new(Purpose::BIP84, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(btc_segwit.purpose(), Purpose::BIP84);
    }

    // Builder tests
    #[test]
    fn test_builder_complete_path() {
        let path = Bip44Path::builder()
            .purpose(Purpose::BIP44)
            .coin_type(CoinType::Bitcoin)
            .account(0)
            .chain(Chain::External)
            .address_index(0)
            .build()
            .unwrap();

        assert_eq!(path.purpose(), Purpose::BIP44);
        assert_eq!(path.coin_type(), CoinType::Bitcoin);
        assert_eq!(path.account(), 0);
        assert_eq!(path.chain(), Chain::External);
        assert_eq!(path.address_index(), 0);
    }

    #[test]
    fn test_builder_with_different_values() {
        let path = Bip44Path::builder()
            .purpose(Purpose::BIP84)
            .coin_type(CoinType::Ethereum)
            .account(5)
            .chain(Chain::Internal)
            .address_index(100)
            .build()
            .unwrap();

        assert_eq!(path.purpose(), Purpose::BIP84);
        assert_eq!(path.coin_type(), CoinType::Ethereum);
        assert_eq!(path.account(), 5);
        assert_eq!(path.chain(), Chain::Internal);
        assert_eq!(path.address_index(), 100);
    }

    #[test]
    fn test_builder_method_chaining() {
        // Test that builder methods can be chained in any order
        let path1 = Bip44Path::builder()
            .address_index(10)
            .chain(Chain::External)
            .account(2)
            .coin_type(CoinType::Litecoin)
            .purpose(Purpose::BIP49)
            .build()
            .unwrap();

        let path2 = Bip44Path::builder()
            .purpose(Purpose::BIP49)
            .coin_type(CoinType::Litecoin)
            .account(2)
            .chain(Chain::External)
            .address_index(10)
            .build()
            .unwrap();

        assert_eq!(path1, path2);
    }

    #[test]
    fn test_builder_missing_purpose() {
        let result = Bip44Path::builder()
            .coin_type(CoinType::Bitcoin)
            .account(0)
            .chain(Chain::External)
            .address_index(0)
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::InvalidPath { .. }));
    }

    #[test]
    fn test_builder_missing_coin_type() {
        let result = Bip44Path::builder()
            .purpose(Purpose::BIP44)
            .account(0)
            .chain(Chain::External)
            .address_index(0)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_missing_account() {
        let result = Bip44Path::builder()
            .purpose(Purpose::BIP44)
            .coin_type(CoinType::Bitcoin)
            .chain(Chain::External)
            .address_index(0)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_missing_chain() {
        let result = Bip44Path::builder()
            .purpose(Purpose::BIP44)
            .coin_type(CoinType::Bitcoin)
            .account(0)
            .address_index(0)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_missing_address_index() {
        let result = Bip44Path::builder()
            .purpose(Purpose::BIP44)
            .coin_type(CoinType::Bitcoin)
            .account(0)
            .chain(Chain::External)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_invalid_account() {
        let result = Bip44Path::builder()
            .purpose(Purpose::BIP44)
            .coin_type(CoinType::Bitcoin)
            .account(MAX_HARDENED_INDEX + 1)
            .chain(Chain::External)
            .address_index(0)
            .build();

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidAccount { .. }));
    }

    #[test]
    fn test_builder_with_custom_coin() {
        let path = Bip44Path::builder()
            .purpose(Purpose::BIP44)
            .coin_type(CoinType::Custom(999))
            .account(0)
            .chain(Chain::External)
            .address_index(0)
            .build()
            .unwrap();

        assert_eq!(path.coin_type(), CoinType::Custom(999));
    }

    #[test]
    fn test_builder_fluent_api() {
        // Test that the builder provides a fluent interface
        let _path = Bip44Path::builder()
            .purpose(Purpose::BIP44)
            .coin_type(CoinType::Bitcoin)
            .account(0)
            .chain(Chain::External)
            .address_index(0)
            .build()
            .unwrap();
    }

    #[test]
    fn test_builder_clone() {
        let builder = Bip44Path::builder()
            .purpose(Purpose::BIP44)
            .coin_type(CoinType::Bitcoin);

        let builder2 = builder.clone();
        
        let path1 = builder
            .account(0)
            .chain(Chain::External)
            .address_index(0)
            .build()
            .unwrap();

        let path2 = builder2
            .account(0)
            .chain(Chain::External)
            .address_index(0)
            .build()
            .unwrap();

        assert_eq!(path1, path2);
    }

    #[test]
    fn test_builder_realistic_scenarios() {
        // Bitcoin receiving
        let btc = Bip44Path::builder()
            .purpose(Purpose::BIP84)
            .coin_type(CoinType::Bitcoin)
            .account(0)
            .chain(Chain::External)
            .address_index(0)
            .build()
            .unwrap();
        assert_eq!(btc.purpose(), Purpose::BIP84);

        // Ethereum change
        let eth = Bip44Path::builder()
            .purpose(Purpose::BIP44)
            .coin_type(CoinType::Ethereum)
            .account(1)
            .chain(Chain::Internal)
            .address_index(5)
            .build()
            .unwrap();
        assert_eq!(eth.chain(), Chain::Internal);
    }

    // Conversion tests
    #[test]
    fn test_to_derivation_path_bitcoin() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let derivation = path.to_derivation_path();

        // Should equal m/44'/0'/0'/0/0
        let expected = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(derivation, expected);
        assert_eq!(derivation.depth(), 5);
    }

    #[test]
    fn test_to_derivation_path_ethereum() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path = Bip44Path::new(Purpose::BIP44, CoinType::Ethereum, 0, Chain::External, 0).unwrap();
        let derivation = path.to_derivation_path();

        // Should equal m/44'/60'/0'/0/0
        let expected = DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_to_derivation_path_with_different_account() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 5, Chain::External, 0).unwrap();
        let derivation = path.to_derivation_path();

        let expected = DerivationPath::from_str("m/44'/0'/5'/0/0").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_to_derivation_path_with_internal_chain() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::Internal, 0).unwrap();
        let derivation = path.to_derivation_path();

        let expected = DerivationPath::from_str("m/44'/0'/0'/1/0").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_to_derivation_path_with_address_index() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 42).unwrap();
        let derivation = path.to_derivation_path();

        let expected = DerivationPath::from_str("m/44'/0'/0'/0/42").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_to_derivation_path_bip84() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path = Bip44Path::new(Purpose::BIP84, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let derivation = path.to_derivation_path();

        // Should equal m/84'/0'/0'/0/0
        let expected = DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_to_derivation_path_custom_coin() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path = Bip44Path::new(Purpose::BIP44, CoinType::Custom(999), 0, Chain::External, 0).unwrap();
        let derivation = path.to_derivation_path();

        let expected = DerivationPath::from_str("m/44'/999'/0'/0/0").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_from_trait_conversion() {
        use khodpay_bip32::DerivationPath;

        let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        
        // Test From<Bip44Path>
        let derivation: DerivationPath = path.into();
        assert_eq!(derivation.depth(), 5);
    }

    #[test]
    fn test_from_ref_trait_conversion() {
        use khodpay_bip32::DerivationPath;

        let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        
        // Test From<&Bip44Path>
        let derivation: DerivationPath = (&path).into();
        assert_eq!(derivation.depth(), 5);

        // Original path should still be usable
        assert_eq!(path.purpose(), Purpose::BIP44);
    }

    #[test]
    fn test_conversion_complex_path() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        // Complex path: m/84'/60'/5'/1/100
        let path = Bip44Path::new(
            Purpose::BIP84,
            CoinType::Ethereum,
            5,
            Chain::Internal,
            100,
        ).unwrap();

        let derivation = path.to_derivation_path();
        let expected = DerivationPath::from_str("m/84'/60'/5'/1/100").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_conversion_preserves_hardening() {
        use khodpay_bip32::ChildNumber;

        let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let derivation = path.to_derivation_path();

        let children = derivation.as_slice();
        
        // First 3 levels should be hardened
        assert!(matches!(children[0], ChildNumber::Hardened(44)));
        assert!(matches!(children[1], ChildNumber::Hardened(0)));
        assert!(matches!(children[2], ChildNumber::Hardened(0)));
        
        // Last 2 levels should be normal
        assert!(matches!(children[3], ChildNumber::Normal(0)));
        assert!(matches!(children[4], ChildNumber::Normal(0)));
    }

    #[test]
    fn test_conversion_all_purposes() {
        for purpose in [Purpose::BIP44, Purpose::BIP49, Purpose::BIP84, Purpose::BIP86] {
            let path = Bip44Path::new(purpose, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
            let derivation = path.to_derivation_path();
            assert_eq!(derivation.depth(), 5);
        }
    }

    #[test]
    fn test_conversion_display_format() {
        let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 5).unwrap();
        let derivation = path.to_derivation_path();
        
        // Check string representation
        assert_eq!(derivation.to_string(), "m/44'/0'/0'/0/5");
    }
}
