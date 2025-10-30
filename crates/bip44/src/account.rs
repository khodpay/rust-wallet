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

#[cfg(feature = "serde")]
mod network_serde {
    use khodpay_bip32::Network;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(network: &Network, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match network {
            Network::BitcoinMainnet => "BitcoinMainnet",
            Network::BitcoinTestnet => "BitcoinTestnet",
        };
        serializer.serialize_str(s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Network, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "BitcoinMainnet" => Ok(Network::BitcoinMainnet),
            "BitcoinTestnet" => Ok(Network::BitcoinTestnet),
            _ => Err(serde::de::Error::custom(format!("Unknown network: {}", s))),
        }
    }
}

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

    /// Derives an extended key for the external (receiving) chain at the specified address index.
    ///
    /// The external chain (chain index 0) is used for receiving addresses that are
    /// meant to be shared with others to receive funds.
    ///
    /// This derives to the full BIP-44 path:
    /// `m/purpose'/coin_type'/account'/0/address_index`
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index to derive (0 to 2^32-1)
    ///
    /// # Errors
    ///
    /// Returns an error if the key derivation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType};
    /// use khodpay_bip32::ExtendedPrivateKey;
    ///
    /// # let seed_bytes = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed_bytes, khodpay_bip32::Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    ///
    /// // Derive the first receiving address
    /// let address_key = account.derive_external(0).unwrap();
    /// ```
    pub fn derive_external(&self, address_index: u32) -> Result<ExtendedPrivateKey> {
        use khodpay_bip32::ChildNumber;

        // Derive chain 0 (external)
        let chain_key = self.extended_key.derive_child(ChildNumber::Normal(0))?;

        // Derive address index
        let address_key = chain_key.derive_child(ChildNumber::Normal(address_index))?;

        Ok(address_key)
    }

    /// Derives an extended key for the internal (change) chain at the specified address index.
    ///
    /// The internal chain (chain index 1) is used for change addresses that are
    /// generated automatically when sending funds.
    ///
    /// This derives to the full BIP-44 path:
    /// `m/purpose'/coin_type'/account'/1/address_index`
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index to derive (0 to 2^32-1)
    ///
    /// # Errors
    ///
    /// Returns an error if the key derivation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType};
    /// use khodpay_bip32::ExtendedPrivateKey;
    ///
    /// # let seed_bytes = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed_bytes, khodpay_bip32::Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    ///
    /// // Derive the first change address
    /// let change_key = account.derive_internal(0).unwrap();
    /// ```
    pub fn derive_internal(&self, address_index: u32) -> Result<ExtendedPrivateKey> {
        use khodpay_bip32::ChildNumber;

        // Derive chain 1 (internal)
        let chain_key = self.extended_key.derive_child(ChildNumber::Normal(1))?;

        // Derive address index
        let address_key = chain_key.derive_child(ChildNumber::Normal(address_index))?;

        Ok(address_key)
    }

    /// Derives an extended key for the specified chain and address index.
    ///
    /// This is a convenience method that combines external and internal derivation.
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain to derive (External or Internal)
    /// * `address_index` - The address index to derive (0 to 2^32-1)
    ///
    /// # Errors
    ///
    /// Returns an error if the key derivation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain};
    /// use khodpay_bip32::ExtendedPrivateKey;
    ///
    /// # let seed_bytes = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed_bytes, khodpay_bip32::Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    ///
    /// // Derive external address
    /// let external_key = account.derive_address(Chain::External, 0).unwrap();
    ///
    /// // Derive internal address
    /// let internal_key = account.derive_address(Chain::Internal, 0).unwrap();
    /// ```
    pub fn derive_address(
        &self,
        chain: crate::Chain,
        address_index: u32,
    ) -> Result<ExtendedPrivateKey> {
        match chain {
            crate::Chain::External => self.derive_external(address_index),
            crate::Chain::Internal => self.derive_internal(address_index),
        }
    }

    /// Derives a range of extended keys for the specified chain.
    ///
    /// This is useful for batch generation of addresses, such as generating
    /// the first 20 receiving addresses for a wallet.
    ///
    /// # Arguments
    ///
    /// * `chain` - The chain to derive (External or Internal)
    /// * `start_index` - The starting address index (inclusive)
    /// * `count` - The number of addresses to derive
    ///
    /// # Errors
    ///
    /// Returns an error if any key derivation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain};
    /// use khodpay_bip32::ExtendedPrivateKey;
    ///
    /// # let seed_bytes = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed_bytes, khodpay_bip32::Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    ///
    /// // Derive the first 10 receiving addresses
    /// let keys = account.derive_address_range(Chain::External, 0, 10).unwrap();
    /// assert_eq!(keys.len(), 10);
    /// ```
    pub fn derive_address_range(
        &self,
        chain: crate::Chain,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<ExtendedPrivateKey>> {
        let mut keys = Vec::with_capacity(count as usize);

        for i in 0..count {
            let index = start_index.saturating_add(i);
            let key = self.derive_address(chain, index)?;
            keys.push(key);
        }

        Ok(keys)
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

    fn create_test_account_key(
        purpose: Purpose,
        coin_type: CoinType,
        account_index: u32,
        network: Network,
    ) -> ExtendedPrivateKey {
        use khodpay_bip32::ChildNumber;

        let seed_bytes = [0u8; 64];
        let master = ExtendedPrivateKey::from_seed(&seed_bytes, network).unwrap();

        // Derive to account level: m/purpose'/coin_type'/account'
        let purpose_key = master
            .derive_child(ChildNumber::Hardened(purpose.value()))
            .unwrap();
        let coin_key = purpose_key
            .derive_child(ChildNumber::Hardened(coin_type.index()))
            .unwrap();
        coin_key
            .derive_child(ChildNumber::Hardened(account_index))
            .unwrap()
    }

    #[test]
    fn test_from_extended_key() {
        let master_key = create_test_master_key();
        let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        assert_eq!(account.purpose(), Purpose::BIP44);
        assert_eq!(account.coin_type(), CoinType::Bitcoin);
        assert_eq!(account.account_index(), 0);
    }

    #[test]
    fn test_purpose_getter() {
        let master_key = create_test_master_key();

        for purpose in [
            Purpose::BIP44,
            Purpose::BIP49,
            Purpose::BIP84,
            Purpose::BIP86,
        ] {
            let account =
                Account::from_extended_key(master_key.clone(), purpose, CoinType::Bitcoin, 0);
            assert_eq!(account.purpose(), purpose);
        }
    }

    #[test]
    fn test_coin_type_getter() {
        let master_key = create_test_master_key();

        let btc_account =
            Account::from_extended_key(master_key.clone(), Purpose::BIP44, CoinType::Bitcoin, 0);
        assert_eq!(btc_account.coin_type(), CoinType::Bitcoin);

        let eth_account =
            Account::from_extended_key(master_key.clone(), Purpose::BIP44, CoinType::Ethereum, 0);
        assert_eq!(eth_account.coin_type(), CoinType::Ethereum);

        let custom_account =
            Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Custom(999), 0);
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
        let account =
            Account::from_extended_key(master_key.clone(), Purpose::BIP44, CoinType::Bitcoin, 0);

        let key = account.extended_key();
        assert_eq!(key.depth(), master_key.depth());
        assert_eq!(key.network(), master_key.network());
    }

    #[test]
    fn test_network_getter() {
        let seed_bytes = [0u8; 64];

        let mainnet_key =
            ExtendedPrivateKey::from_seed(&seed_bytes, Network::BitcoinMainnet).unwrap();
        let mainnet_account =
            Account::from_extended_key(mainnet_key, Purpose::BIP44, CoinType::Bitcoin, 0);
        assert_eq!(mainnet_account.network(), Network::BitcoinMainnet);

        let testnet_key =
            ExtendedPrivateKey::from_seed(&seed_bytes, Network::BitcoinTestnet).unwrap();
        let testnet_account =
            Account::from_extended_key(testnet_key, Purpose::BIP44, CoinType::BitcoinTestnet, 0);
        assert_eq!(testnet_account.network(), Network::BitcoinTestnet);
    }

    #[test]
    fn test_account_clone() {
        let master_key = create_test_master_key();
        let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let cloned = account.clone();
        assert_eq!(cloned.purpose(), account.purpose());
        assert_eq!(cloned.coin_type(), account.coin_type());
        assert_eq!(cloned.account_index(), account.account_index());
    }

    #[test]
    fn test_multiple_accounts_same_coin() {
        let master_key = create_test_master_key();

        let account0 =
            Account::from_extended_key(master_key.clone(), Purpose::BIP44, CoinType::Bitcoin, 0);
        let account1 = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 1);

        assert_eq!(account0.account_index(), 0);
        assert_eq!(account1.account_index(), 1);
        assert_eq!(account0.coin_type(), account1.coin_type());
    }

    #[test]
    fn test_multiple_purposes_same_coin() {
        let master_key = create_test_master_key();

        let bip44 =
            Account::from_extended_key(master_key.clone(), Purpose::BIP44, CoinType::Bitcoin, 0);
        let bip84 = Account::from_extended_key(master_key, Purpose::BIP84, CoinType::Bitcoin, 0);

        assert_eq!(bip44.purpose(), Purpose::BIP44);
        assert_eq!(bip84.purpose(), Purpose::BIP84);
        assert_eq!(bip44.coin_type(), bip84.coin_type());
    }

    #[test]
    fn test_debug_format() {
        let master_key = create_test_master_key();
        let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let debug_str = format!("{:?}", account);
        assert!(debug_str.contains("Account"));
    }

    #[test]
    fn test_account_with_different_networks() {
        let seed_bytes = [0u8; 64];

        for network in [Network::BitcoinMainnet, Network::BitcoinTestnet] {
            let key = ExtendedPrivateKey::from_seed(&seed_bytes, network).unwrap();
            let account = Account::from_extended_key(key, Purpose::BIP44, CoinType::Bitcoin, 0);
            assert_eq!(account.network(), network);
        }
    }

    // Derivation tests
    #[test]
    fn test_derive_external() {
        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let address_key = account.derive_external(0).unwrap();

        // Verify depth: account (3) + chain (4) + address (5)
        assert_eq!(address_key.depth(), 5);
    }

    #[test]
    fn test_derive_internal() {
        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let change_key = account.derive_internal(0).unwrap();

        // Verify depth: account (3) + chain (4) + address (5)
        assert_eq!(change_key.depth(), 5);
    }

    #[test]
    fn test_derive_external_multiple_indices() {
        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let key0 = account.derive_external(0).unwrap();
        let key1 = account.derive_external(1).unwrap();
        let key10 = account.derive_external(10).unwrap();

        // All should have depth 5
        assert_eq!(key0.depth(), 5);
        assert_eq!(key1.depth(), 5);
        assert_eq!(key10.depth(), 5);

        // Keys should be different
        assert_ne!(key0.private_key(), key1.private_key());
        assert_ne!(key1.private_key(), key10.private_key());
    }

    #[test]
    fn test_derive_internal_multiple_indices() {
        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let key0 = account.derive_internal(0).unwrap();
        let key1 = account.derive_internal(1).unwrap();
        let key5 = account.derive_internal(5).unwrap();

        // All should have depth 5
        assert_eq!(key0.depth(), 5);
        assert_eq!(key1.depth(), 5);
        assert_eq!(key5.depth(), 5);

        // Keys should be different
        assert_ne!(key0.private_key(), key1.private_key());
        assert_ne!(key1.private_key(), key5.private_key());
    }

    #[test]
    fn test_external_and_internal_keys_differ() {
        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let external = account.derive_external(0).unwrap();
        let internal = account.derive_internal(0).unwrap();

        // Same index but different chains should produce different keys
        assert_ne!(external.private_key(), internal.private_key());
    }

    #[test]
    fn test_derive_sequential_external() {
        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        // Derive first 5 receiving addresses
        let keys: Vec<_> = (0..5)
            .map(|i| account.derive_external(i).unwrap())
            .collect();

        assert_eq!(keys.len(), 5);

        // All keys should be unique
        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i].private_key(), keys[j].private_key());
            }
        }
    }

    #[test]
    fn test_derive_sequential_internal() {
        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        // Derive first 5 change addresses
        let keys: Vec<_> = (0..5)
            .map(|i| account.derive_internal(i).unwrap())
            .collect();

        assert_eq!(keys.len(), 5);

        // All keys should be unique
        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i].private_key(), keys[j].private_key());
            }
        }
    }

    #[test]
    fn test_derive_with_different_purposes() {
        let bip44_account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let bip84_account_key = create_test_account_key(
            Purpose::BIP84,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );

        let bip44_account =
            Account::from_extended_key(bip44_account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
        let bip84_account =
            Account::from_extended_key(bip84_account_key, Purpose::BIP84, CoinType::Bitcoin, 0);

        let bip44_derived_key = bip44_account.derive_external(0).unwrap();
        let bip84_derived_key = bip84_account.derive_external(0).unwrap();

        // Different purposes should produce different keys
        assert_ne!(
            bip44_derived_key.private_key(),
            bip84_derived_key.private_key()
        );
    }

    #[test]
    fn test_derive_with_different_coins() {
        let btc_account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let eth_account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Ethereum,
            0,
            Network::BitcoinMainnet,
        );

        let btc_account =
            Account::from_extended_key(btc_account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
        let eth_account =
            Account::from_extended_key(eth_account_key, Purpose::BIP44, CoinType::Ethereum, 0);

        let btc_derived_key = btc_account.derive_external(0).unwrap();
        let eth_derived_key = eth_account.derive_external(0).unwrap();

        // Different coins should produce different keys
        assert_ne!(btc_derived_key.private_key(), eth_derived_key.private_key());
    }

    #[test]
    fn test_derive_with_different_accounts() {
        let account0_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account1_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            1,
            Network::BitcoinMainnet,
        );

        let account0 =
            Account::from_extended_key(account0_key, Purpose::BIP44, CoinType::Bitcoin, 0);
        let account1 =
            Account::from_extended_key(account1_key, Purpose::BIP44, CoinType::Bitcoin, 1);

        let key0 = account0.derive_external(0).unwrap();
        let key1 = account1.derive_external(0).unwrap();

        // Different accounts should produce different keys
        assert_ne!(key0.private_key(), key1.private_key());
    }

    #[test]
    fn test_derive_large_index() {
        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        // Test with large index
        let key = account.derive_external(100000).unwrap();
        assert_eq!(key.depth(), 5);
    }

    #[test]
    fn test_derive_max_index() {
        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        // Test with maximum index
        let key = account.derive_external(u32::MAX).unwrap();
        assert_eq!(key.depth(), 5);
    }

    #[test]
    fn test_derive_network_preserved() {
        for network in [Network::BitcoinMainnet, Network::BitcoinTestnet] {
            let account_key =
                create_test_account_key(Purpose::BIP44, CoinType::Bitcoin, 0, network);
            let account =
                Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

            let external = account.derive_external(0).unwrap();
            let internal = account.derive_internal(0).unwrap();

            assert_eq!(external.network(), network);
            assert_eq!(internal.network(), network);
        }
    }

    #[test]
    fn test_derive_deterministic() {
        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        // Derive the same key twice
        let key1 = account.derive_external(5).unwrap();
        let key2 = account.derive_external(5).unwrap();

        // Should be identical
        assert_eq!(key1.private_key(), key2.private_key());
        assert_eq!(key1.chain_code(), key2.chain_code());
    }

    // derive_address tests
    #[test]
    fn test_derive_address_external() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let key1 = account.derive_address(Chain::External, 0).unwrap();
        let key2 = account.derive_external(0).unwrap();

        // Should produce same key as derive_external
        assert_eq!(key1.private_key(), key2.private_key());
    }

    #[test]
    fn test_derive_address_internal() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let key1 = account.derive_address(Chain::Internal, 0).unwrap();
        let key2 = account.derive_internal(0).unwrap();

        // Should produce same key as derive_internal
        assert_eq!(key1.private_key(), key2.private_key());
    }

    #[test]
    fn test_derive_address_both_chains() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let external = account.derive_address(Chain::External, 5).unwrap();
        let internal = account.derive_address(Chain::Internal, 5).unwrap();

        // Different chains should produce different keys
        assert_ne!(external.private_key(), internal.private_key());
    }

    // derive_address_range tests
    #[test]
    fn test_derive_address_range_basic() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let keys = account.derive_address_range(Chain::External, 0, 5).unwrap();

        assert_eq!(keys.len(), 5);

        // Verify all keys are unique
        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                assert_ne!(keys[i].private_key(), keys[j].private_key());
            }
        }
    }

    #[test]
    fn test_derive_address_range_matches_individual() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let range_keys = account.derive_address_range(Chain::External, 0, 5).unwrap();

        // Verify each key matches individual derivation
        for (i, key) in range_keys.iter().enumerate() {
            let individual_key = account.derive_address(Chain::External, i as u32).unwrap();
            assert_eq!(key.private_key(), individual_key.private_key());
        }
    }

    #[test]
    fn test_derive_address_range_internal_chain() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let keys = account
            .derive_address_range(Chain::Internal, 0, 10)
            .unwrap();

        assert_eq!(keys.len(), 10);

        // All should have depth 5
        for key in &keys {
            assert_eq!(key.depth(), 5);
        }
    }

    #[test]
    fn test_derive_address_range_with_offset() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let keys = account
            .derive_address_range(Chain::External, 10, 5)
            .unwrap();

        assert_eq!(keys.len(), 5);

        // Verify first key matches index 10
        let key10 = account.derive_address(Chain::External, 10).unwrap();
        assert_eq!(keys[0].private_key(), key10.private_key());

        // Verify last key matches index 14
        let key14 = account.derive_address(Chain::External, 14).unwrap();
        assert_eq!(keys[4].private_key(), key14.private_key());
    }

    #[test]
    fn test_derive_address_range_empty() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let keys = account.derive_address_range(Chain::External, 0, 0).unwrap();

        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_derive_address_range_single() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let keys = account.derive_address_range(Chain::External, 5, 1).unwrap();

        assert_eq!(keys.len(), 1);

        let key5 = account.derive_address(Chain::External, 5).unwrap();
        assert_eq!(keys[0].private_key(), key5.private_key());
    }

    #[test]
    fn test_derive_address_range_large_count() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let keys = account
            .derive_address_range(Chain::External, 0, 100)
            .unwrap();

        assert_eq!(keys.len(), 100);

        // Spot check a few keys
        let key0 = account.derive_address(Chain::External, 0).unwrap();
        let key50 = account.derive_address(Chain::External, 50).unwrap();
        let key99 = account.derive_address(Chain::External, 99).unwrap();

        assert_eq!(keys[0].private_key(), key0.private_key());
        assert_eq!(keys[50].private_key(), key50.private_key());
        assert_eq!(keys[99].private_key(), key99.private_key());
    }

    #[test]
    fn test_derive_address_range_gap_limit() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        // Typical gap limit for BIP-44 is 20
        let keys = account
            .derive_address_range(Chain::External, 0, 20)
            .unwrap();

        assert_eq!(keys.len(), 20);
    }

    #[test]
    fn test_derive_address_range_sequential_batches() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        let batch1 = account
            .derive_address_range(Chain::External, 0, 10)
            .unwrap();
        let batch2 = account
            .derive_address_range(Chain::External, 10, 10)
            .unwrap();

        // Last key of batch1 should be different from first key of batch2
        assert_ne!(batch1[9].private_key(), batch2[0].private_key());

        // Verify continuity
        let key9 = account.derive_address(Chain::External, 9).unwrap();
        let key10 = account.derive_address(Chain::External, 10).unwrap();

        assert_eq!(batch1[9].private_key(), key9.private_key());
        assert_eq!(batch2[0].private_key(), key10.private_key());
    }

    #[test]
    fn test_derive_address_range_overflow_protection() {
        use crate::Chain;

        let account_key = create_test_account_key(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Network::BitcoinMainnet,
        );
        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

        // Start near the end of u32 range
        let keys = account
            .derive_address_range(Chain::External, u32::MAX - 5, 10)
            .unwrap();

        // Should saturate at u32::MAX
        assert_eq!(keys.len(), 10);
    }
}

/// Serializable account metadata without private keys.
///
/// This struct contains only the metadata about an account,
/// without the sensitive extended private key. It's safe to
/// serialize and persist.
///
/// # Security
///
/// This struct does NOT contain private keys and is safe to serialize.
/// Use this for persisting wallet state without exposing keys.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::{AccountMetadata, Purpose, CoinType};
/// use khodpay_bip32::Network;
///
/// let metadata = AccountMetadata::new(
///     Purpose::BIP44,
///     CoinType::Bitcoin,
///     0,
///     Network::BitcoinMainnet,
/// );
///
/// assert_eq!(metadata.purpose(), Purpose::BIP44);
/// assert_eq!(metadata.coin_type(), CoinType::Bitcoin);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccountMetadata {
    purpose: Purpose,
    coin_type: CoinType,
    account_index: u32,
    #[cfg_attr(feature = "serde", serde(with = "network_serde"))]
    network: khodpay_bip32::Network,
}

impl AccountMetadata {
    /// Creates new account metadata.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{AccountMetadata, Purpose, CoinType};
    /// use khodpay_bip32::Network;
    ///
    /// let metadata = AccountMetadata::new(
    ///     Purpose::BIP44,
    ///     CoinType::Bitcoin,
    ///     0,
    ///     Network::BitcoinMainnet,
    /// );
    /// ```
    pub fn new(
        purpose: Purpose,
        coin_type: CoinType,
        account_index: u32,
        network: khodpay_bip32::Network,
    ) -> Self {
        Self {
            purpose,
            coin_type,
            account_index,
            network,
        }
    }

    /// Creates metadata from an Account.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, AccountMetadata, Purpose, CoinType};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// # let seed = [0u8; 64];
    /// # let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// # let purpose_key = master.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// # let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let metadata = AccountMetadata::from_account(&account);
    ///
    /// assert_eq!(metadata.purpose(), Purpose::BIP44);
    /// ```
    pub fn from_account(account: &Account) -> Self {
        Self {
            purpose: account.purpose(),
            coin_type: account.coin_type(),
            account_index: account.account_index(),
            network: account.network(),
        }
    }

    /// Returns the purpose.
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// Returns the coin type.
    pub fn coin_type(&self) -> CoinType {
        self.coin_type
    }

    /// Returns the account index.
    pub fn account_index(&self) -> u32 {
        self.account_index
    }

    /// Returns the network.
    pub fn network(&self) -> khodpay_bip32::Network {
        self.network
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    #[test]
    fn test_account_metadata_serialize() {
        let metadata = AccountMetadata::new(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            khodpay_bip32::Network::BitcoinMainnet,
        );

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("BIP44"));
        assert!(json.contains("Bitcoin"));
    }

    #[test]
    fn test_account_metadata_deserialize() {
        let json = r#"{"purpose":"BIP44","coin_type":"Bitcoin","account_index":0,"network":"BitcoinMainnet"}"#;
        let metadata: AccountMetadata = serde_json::from_str(json).unwrap();

        assert_eq!(metadata.purpose(), Purpose::BIP44);
        assert_eq!(metadata.coin_type(), CoinType::Bitcoin);
        assert_eq!(metadata.account_index(), 0);
    }

    #[test]
    fn test_account_metadata_round_trip() {
        let metadata = AccountMetadata::new(
            Purpose::BIP84,
            CoinType::Ethereum,
            5,
            khodpay_bip32::Network::BitcoinMainnet,
        );

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: AccountMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(metadata, deserialized);
    }

    #[test]
    fn test_account_metadata_from_account() {
        use khodpay_bip32::{ChildNumber, ExtendedPrivateKey, Network};

        let seed = [0u8; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let purpose_key = master.derive_child(ChildNumber::Hardened(44)).unwrap();
        let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
        let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();

        let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
        let metadata = AccountMetadata::from_account(&account);

        assert_eq!(metadata.purpose(), Purpose::BIP44);
        assert_eq!(metadata.coin_type(), CoinType::Bitcoin);
        assert_eq!(metadata.account_index(), 0);
        assert_eq!(metadata.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_account_metadata_clone() {
        let metadata1 = AccountMetadata::new(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            khodpay_bip32::Network::BitcoinMainnet,
        );
        let metadata2 = metadata1.clone();

        assert_eq!(metadata1, metadata2);
    }

    #[test]
    fn test_account_metadata_debug() {
        let metadata = AccountMetadata::new(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            khodpay_bip32::Network::BitcoinMainnet,
        );

        let debug_str = format!("{:?}", metadata);
        assert!(debug_str.contains("AccountMetadata"));
    }
}
