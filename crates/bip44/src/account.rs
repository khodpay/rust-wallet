//! BIP-44 account abstraction and key derivation.
//!
//! This module provides the [`Account`] type which wraps a BIP-32 extended key
//! with BIP-44 metadata (purpose, coin type, account index). It manages the
//! account level (m/purpose'/coin_type'/account') of the BIP-44 hierarchy.
//!
//! # Account Level
//!
//! In BIP-44, the account level is the third level of the derivation path:
//!
//! ```text
//! m / purpose' / coin_type' / account' / chain / address_index
//!                             ^^^^^^^^^
//!                             Account level
//! ```
//!
//! From an account, you can derive:
//! - External (receiving) addresses: m/purpose'/coin_type'/account'/0/*
//! - Internal (change) addresses: m/purpose'/coin_type'/account'/1/*
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip44::{Account, Purpose, CoinType};
//! use khodpay_bip32::ExtendedPrivateKey;
//!
//! # let seed_bytes = [0u8; 64];
//! # let master_key = khodpay_bip32::ExtendedPrivateKey::from_seed(&seed_bytes, khodpay_bip32::Network::BitcoinMainnet).unwrap();
//! // Create an account from a BIP-32 extended key
//! let account = Account::from_extended_key(
//!     master_key,
//!     Purpose::BIP44,
//!     CoinType::Bitcoin,
//!     0,
//! );
//!
//! assert_eq!(account.purpose(), Purpose::BIP44);
//! assert_eq!(account.coin_type(), CoinType::Bitcoin);
//! assert_eq!(account.account_index(), 0);
//! ```

use crate::{CoinType, Purpose, Result};
use khodpay_bip32::ExtendedPrivateKey;

/// A BIP-44 account wrapping a BIP-32 extended private key with metadata.
///
/// An account represents the third level of the BIP-44 hierarchy
/// (m/purpose'/coin_type'/account') and provides methods to derive
/// receiving and change addresses.
///
/// # Structure
///
/// The account stores:
/// - The BIP-32 extended private key at the account level
/// - BIP-44 metadata: purpose, coin type, and account index
///
/// # Address Derivation
///
/// From an account, you can derive:
/// - **External chain** (receiving addresses): account/0/*
/// - **Internal chain** (change addresses): account/1/*
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::{Account, Purpose, CoinType};
/// use khodpay_bip32::ExtendedPrivateKey;
///
/// # let seed_bytes = [0u8; 64];
/// # let master_key = ExtendedPrivateKey::from_seed(&seed_bytes, khodpay_bip32::Network::BitcoinMainnet).unwrap();
/// // Create Bitcoin account 0 using BIP-44
/// let account = Account::from_extended_key(
///     master_key,
///     Purpose::BIP44,
///     CoinType::Bitcoin,
///     0,
/// );
/// ```
#[derive(Debug, Clone)]
pub struct Account {
    /// The BIP-32 extended private key at the account level
    extended_key: ExtendedPrivateKey,
    /// The BIP standard being used (BIP-44, BIP-49, BIP-84, or BIP-86)
    purpose: Purpose,
    /// The cryptocurrency type
    coin_type: CoinType,
    /// The account index
    account_index: u32,
}

impl Account {
    /// Creates a new account from a BIP-32 extended private key.
    ///
    /// The extended key should already be at the account level
    /// (m/purpose'/coin_type'/account') in the BIP-44 hierarchy.
    ///
    /// # Arguments
    ///
    /// * `extended_key` - The BIP-32 extended private key at account level
    /// * `purpose` - The BIP standard (BIP-44, BIP-49, BIP-84, or BIP-86)
    /// * `coin_type` - The cryptocurrency type
    /// * `account_index` - The account index
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType};
    /// use khodpay_bip32::ExtendedPrivateKey;
    ///
    /// # let seed_bytes = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed_bytes, khodpay_bip32::Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(
    ///     master_key,
    ///     Purpose::BIP84,
    ///     CoinType::Bitcoin,
    ///     0,
    /// );
    ///
    /// assert_eq!(account.purpose(), Purpose::BIP84);
    /// assert_eq!(account.account_index(), 0);
    /// ```
    pub fn from_extended_key(
        extended_key: ExtendedPrivateKey,
        purpose: Purpose,
        coin_type: CoinType,
        account_index: u32,
    ) -> Self {
        Self {
            extended_key,
            purpose,
            coin_type,
            account_index,
        }
    }

    /// Returns the BIP standard (purpose) for this account.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType};
    /// # use khodpay_bip32::ExtendedPrivateKey;
    ///
    /// # let seed_bytes = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed_bytes, khodpay_bip32::Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// assert_eq!(account.purpose(), Purpose::BIP44);
    /// ```
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// Returns the cryptocurrency type for this account.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType};
    /// # use khodpay_bip32::ExtendedPrivateKey;
    ///
    /// # let seed_bytes = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed_bytes, khodpay_bip32::Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Ethereum, 0);
    /// assert_eq!(account.coin_type(), CoinType::Ethereum);
    /// ```
    pub const fn coin_type(&self) -> CoinType {
        self.coin_type
    }

    /// Returns the account index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType};
    /// # use khodpay_bip32::ExtendedPrivateKey;
    ///
    /// # let seed_bytes = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed_bytes, khodpay_bip32::Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 5);
    /// assert_eq!(account.account_index(), 5);
    /// ```
    pub const fn account_index(&self) -> u32 {
        self.account_index
    }

    /// Returns a reference to the extended private key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType};
    /// # use khodpay_bip32::ExtendedPrivateKey;
    ///
    /// # let seed_bytes = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed_bytes, khodpay_bip32::Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key.clone(), Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let key = account.extended_key();
    /// # assert_eq!(key.depth(), master_key.depth());
    /// ```
    pub const fn extended_key(&self) -> &ExtendedPrivateKey {
        &self.extended_key
    }

    /// Returns the network for this account.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType};
    /// use khodpay_bip32::Network;
    /// # use khodpay_bip32::ExtendedPrivateKey;
    ///
    /// # let seed_bytes = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed_bytes, Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// assert_eq!(account.network(), Network::BitcoinMainnet);
    /// ```
    pub fn network(&self) -> khodpay_bip32::Network {
        self.extended_key.network()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use khodpay_bip32::Network;

    fn create_test_master_key() -> ExtendedPrivateKey {
        let seed_bytes = [0u8; 64];
        ExtendedPrivateKey::from_seed(&seed_bytes, Network::BitcoinMainnet).unwrap()
    }

    #[test]
    fn test_from_extended_key() {
        let master_key = create_test_master_key();
        let account = Account::from_extended_key(
            master_key,
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
        );

        assert_eq!(account.purpose(), Purpose::BIP44);
        assert_eq!(account.coin_type(), CoinType::Bitcoin);
        assert_eq!(account.account_index(), 0);
    }

    #[test]
    fn test_purpose_getter() {
        let master_key = create_test_master_key();
        
        for purpose in [Purpose::BIP44, Purpose::BIP49, Purpose::BIP84, Purpose::BIP86] {
            let account = Account::from_extended_key(
                master_key.clone(),
                purpose,
                CoinType::Bitcoin,
                0,
            );
            assert_eq!(account.purpose(), purpose);
        }
    }

    #[test]
    fn test_coin_type_getter() {
        let master_key = create_test_master_key();
        
        let btc_account = Account::from_extended_key(
            master_key.clone(),
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
        );
        assert_eq!(btc_account.coin_type(), CoinType::Bitcoin);

        let eth_account = Account::from_extended_key(
            master_key.clone(),
            Purpose::BIP44,
            CoinType::Ethereum,
            0,
        );
        assert_eq!(eth_account.coin_type(), CoinType::Ethereum);

        let custom_account = Account::from_extended_key(
            master_key,
            Purpose::BIP44,
            CoinType::Custom(999),
            0,
        );
        assert_eq!(custom_account.coin_type(), CoinType::Custom(999));
    }

    #[test]
    fn test_account_index_getter() {
        let master_key = create_test_master_key();
        
        for index in [0, 1, 5, 100, 1000] {
            let account = Account::from_extended_key(
                master_key.clone(),
                Purpose::BIP44,
                CoinType::Bitcoin,
                index,
            );
            assert_eq!(account.account_index(), index);
        }
    }

    #[test]
    fn test_extended_key_getter() {
        let master_key = create_test_master_key();
        let account = Account::from_extended_key(
            master_key.clone(),
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
        );

        let key = account.extended_key();
        assert_eq!(key.depth(), master_key.depth());
        assert_eq!(key.network(), master_key.network());
    }

    #[test]
    fn test_network_getter() {
        let seed_bytes = [0u8; 64];
        
        let mainnet_key = ExtendedPrivateKey::from_seed(&seed_bytes, Network::BitcoinMainnet).unwrap();
        let mainnet_account = Account::from_extended_key(
            mainnet_key,
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
        );
        assert_eq!(mainnet_account.network(), Network::BitcoinMainnet);

        let testnet_key = ExtendedPrivateKey::from_seed(&seed_bytes, Network::BitcoinTestnet).unwrap();
        let testnet_account = Account::from_extended_key(
            testnet_key,
            Purpose::BIP44,
            CoinType::BitcoinTestnet,
            0,
        );
        assert_eq!(testnet_account.network(), Network::BitcoinTestnet);
    }

    #[test]
    fn test_account_clone() {
        let master_key = create_test_master_key();
        let account = Account::from_extended_key(
            master_key,
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
        );

        let cloned = account.clone();
        assert_eq!(cloned.purpose(), account.purpose());
        assert_eq!(cloned.coin_type(), account.coin_type());
        assert_eq!(cloned.account_index(), account.account_index());
    }

    #[test]
    fn test_multiple_accounts_same_coin() {
        let master_key = create_test_master_key();
        
        let account0 = Account::from_extended_key(
            master_key.clone(),
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
        );
        let account1 = Account::from_extended_key(
            master_key,
            Purpose::BIP44,
            CoinType::Bitcoin,
            1,
        );

        assert_eq!(account0.account_index(), 0);
        assert_eq!(account1.account_index(), 1);
        assert_eq!(account0.coin_type(), account1.coin_type());
    }

    #[test]
    fn test_multiple_purposes_same_coin() {
        let master_key = create_test_master_key();
        
        let bip44 = Account::from_extended_key(
            master_key.clone(),
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
        );
        let bip84 = Account::from_extended_key(
            master_key,
            Purpose::BIP84,
            CoinType::Bitcoin,
            0,
        );

        assert_eq!(bip44.purpose(), Purpose::BIP44);
        assert_eq!(bip84.purpose(), Purpose::BIP84);
        assert_eq!(bip44.coin_type(), bip84.coin_type());
    }

    #[test]
    fn test_debug_format() {
        let master_key = create_test_master_key();
        let account = Account::from_extended_key(
            master_key,
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
        );

        let debug_str = format!("{:?}", account);
        assert!(debug_str.contains("Account"));
    }

    #[test]
    fn test_account_with_different_networks() {
        let seed_bytes = [0u8; 64];

        for network in [Network::BitcoinMainnet, Network::BitcoinTestnet] {
            let key = ExtendedPrivateKey::from_seed(&seed_bytes, network).unwrap();
            let account = Account::from_extended_key(
                key,
                Purpose::BIP44,
                CoinType::Bitcoin,
                0,
            );
            assert_eq!(account.network(), network);
        }
    }
}
