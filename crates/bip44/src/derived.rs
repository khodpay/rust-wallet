//! Derived address with metadata.
//!
//! This module provides a wrapper for derived keys with BIP-44 metadata.
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
//! use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
//!
//! let seed = [0u8; 64];
//! let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
//!
//! // Derive to account level
//! let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
//! let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
//! let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
//!
//! let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
//! let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();
//!
//! assert_eq!(derived.index(), 0);
//! assert_eq!(derived.chain(), Chain::External);
//! ```

use crate::{Account, Bip44Path, Chain, CoinType, Purpose, Result};
use khodpay_bip32::ExtendedPrivateKey;

/// A derived address with BIP-44 metadata.
///
/// This struct wraps an extended private key along with its BIP-44 derivation
/// path information, providing convenient access to metadata.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
/// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
///
/// let seed = [0u8; 64];
/// let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
///
/// // Derive to account level
/// let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
/// let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
/// let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
///
/// let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
/// let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();
///
/// println!("Address at {}", derived.path());
/// ```
#[derive(Debug, Clone)]
pub struct DerivedAddress {
    /// The extended private key
    key: ExtendedPrivateKey,
    /// The BIP-44 path
    path: Bip44Path,
    /// The chain (external or internal)
    chain: Chain,
    /// The address index
    index: u32,
}

impl DerivedAddress {
    /// Creates a new derived address from an account.
    ///
    /// # Arguments
    ///
    /// * `account` - The account to derive from
    /// * `chain` - The chain (external or internal)
    /// * `index` - The address index
    ///
    /// # Returns
    ///
    /// A new `DerivedAddress` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// let seed = [0u8; 64];
    /// let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    ///
    /// let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    ///
    /// let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let derived = DerivedAddress::new(&account, Chain::External, 5).unwrap();
    ///
    /// assert_eq!(derived.index(), 5);
    /// ```
    pub fn new(account: &Account, chain: Chain, index: u32) -> Result<Self> {
        let key = match chain {
            Chain::External => account.derive_external(index)?,
            Chain::Internal => account.derive_internal(index)?,
        };

        let path = Bip44Path::new(
            account.purpose(),
            account.coin_type(),
            account.account_index(),
            chain,
            index,
        )?;

        Ok(Self {
            key,
            path,
            chain,
            index,
        })
    }

    /// Returns a reference to the extended private key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// # let seed = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// # let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// # let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();
    ///
    /// let key = derived.key();
    /// assert_eq!(key.depth(), 5);
    /// ```
    pub fn key(&self) -> &ExtendedPrivateKey {
        &self.key
    }

    /// Returns the BIP-44 path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// # let seed = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// # let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// # let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();
    ///
    /// let path = derived.path();
    /// assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    /// ```
    pub fn path(&self) -> &Bip44Path {
        &self.path
    }

    /// Returns the chain (external or internal).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// # let seed = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// # let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// # let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();
    ///
    /// assert_eq!(derived.chain(), Chain::External);
    /// ```
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// Returns the address index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// # let seed = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// # let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// # let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let derived = DerivedAddress::new(&account, Chain::External, 42).unwrap();
    ///
    /// assert_eq!(derived.index(), 42);
    /// ```
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Returns the purpose (BIP standard).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// # let seed = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// # let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// # let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();
    ///
    /// assert_eq!(derived.purpose(), Purpose::BIP44);
    /// ```
    pub fn purpose(&self) -> Purpose {
        self.path.purpose()
    }

    /// Returns the coin type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// # let seed = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// # let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// # let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();
    ///
    /// assert_eq!(derived.coin_type(), CoinType::Bitcoin);
    /// ```
    pub fn coin_type(&self) -> CoinType {
        self.path.coin_type()
    }

    /// Returns the account index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// # let seed = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// # let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// # let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();
    ///
    /// assert_eq!(derived.account_index(), 0);
    /// ```
    pub fn account_index(&self) -> u32 {
        self.path.account()
    }

    /// Checks if this is an external (receiving) address.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// # let seed = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// # let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// # let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let external = DerivedAddress::new(&account, Chain::External, 0).unwrap();
    /// let internal = DerivedAddress::new(&account, Chain::Internal, 0).unwrap();
    ///
    /// assert!(external.is_external());
    /// assert!(!internal.is_external());
    /// ```
    pub fn is_external(&self) -> bool {
        self.chain == Chain::External
    }

    /// Checks if this is an internal (change) address.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// # let seed = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// # let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// # let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let external = DerivedAddress::new(&account, Chain::External, 0).unwrap();
    /// let internal = DerivedAddress::new(&account, Chain::Internal, 0).unwrap();
    ///
    /// assert!(!external.is_internal());
    /// assert!(internal.is_internal());
    /// ```
    pub fn is_internal(&self) -> bool {
        self.chain == Chain::Internal
    }

    /// Returns the network.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, DerivedAddress};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// # let seed = [0u8; 64];
    /// # let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// # let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    /// # let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    /// # let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    /// let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();
    ///
    /// assert_eq!(derived.network(), Network::BitcoinMainnet);
    /// ```
    pub fn network(&self) -> khodpay_bip32::Network {
        self.key.network()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use khodpay_bip32::{ChildNumber, ExtendedPrivateKey, Network};

    fn create_test_account() -> Account {
        let seed = [0u8; 64];
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Derive to account level: m/44'/0'/0'
        let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
        let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
        let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();

        Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0)
    }

    #[test]
    fn test_derived_address_new_external() {
        let account = create_test_account();
        let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();

        assert_eq!(derived.index(), 0);
        assert_eq!(derived.chain(), Chain::External);
        assert!(derived.is_external());
        assert!(!derived.is_internal());
    }

    #[test]
    fn test_derived_address_new_internal() {
        let account = create_test_account();
        let derived = DerivedAddress::new(&account, Chain::Internal, 0).unwrap();

        assert_eq!(derived.index(), 0);
        assert_eq!(derived.chain(), Chain::Internal);
        assert!(!derived.is_external());
        assert!(derived.is_internal());
    }

    #[test]
    fn test_derived_address_key() {
        let account = create_test_account();
        let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();

        let key = derived.key();
        assert_eq!(key.depth(), 5);
    }

    #[test]
    fn test_derived_address_path() {
        let account = create_test_account();
        let derived = DerivedAddress::new(&account, Chain::External, 5).unwrap();

        let path = derived.path();
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/5");
    }

    #[test]
    fn test_derived_address_metadata() {
        let account = create_test_account();
        let derived = DerivedAddress::new(&account, Chain::External, 10).unwrap();

        assert_eq!(derived.purpose(), Purpose::BIP44);
        assert_eq!(derived.coin_type(), CoinType::Bitcoin);
        assert_eq!(derived.account_index(), 0);
        assert_eq!(derived.index(), 10);
    }

    #[test]
    fn test_derived_address_network() {
        let account = create_test_account();
        let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();

        assert_eq!(derived.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_derived_address_clone() {
        let account = create_test_account();
        let derived1 = DerivedAddress::new(&account, Chain::External, 0).unwrap();
        let derived2 = derived1.clone();

        assert_eq!(derived1.index(), derived2.index());
        assert_eq!(derived1.chain(), derived2.chain());
    }

    #[test]
    fn test_derived_address_debug() {
        let account = create_test_account();
        let derived = DerivedAddress::new(&account, Chain::External, 0).unwrap();

        let debug_str = format!("{:?}", derived);
        assert!(debug_str.contains("DerivedAddress"));
    }

    #[test]
    fn test_derived_address_multiple_indices() {
        let account = create_test_account();

        let addr0 = DerivedAddress::new(&account, Chain::External, 0).unwrap();
        let addr1 = DerivedAddress::new(&account, Chain::External, 1).unwrap();
        let addr2 = DerivedAddress::new(&account, Chain::External, 2).unwrap();

        assert_eq!(addr0.index(), 0);
        assert_eq!(addr1.index(), 1);
        assert_eq!(addr2.index(), 2);
    }

    #[test]
    fn test_derived_address_both_chains() {
        let account = create_test_account();

        let external = DerivedAddress::new(&account, Chain::External, 0).unwrap();
        let internal = DerivedAddress::new(&account, Chain::Internal, 0).unwrap();

        assert_eq!(external.path().to_string(), "m/44'/0'/0'/0/0");
        assert_eq!(internal.path().to_string(), "m/44'/0'/0'/1/0");
    }

    #[test]
    fn test_derived_address_large_index() {
        let account = create_test_account();
        let derived = DerivedAddress::new(&account, Chain::External, 1000).unwrap();

        assert_eq!(derived.index(), 1000);
        assert_eq!(derived.path().to_string(), "m/44'/0'/0'/0/1000");
    }
}
