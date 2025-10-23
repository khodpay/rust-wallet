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
}
