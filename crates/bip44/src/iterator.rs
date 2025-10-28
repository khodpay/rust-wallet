//! Iterator for sequential address generation.
//!
//! This module provides iterators for traversing addresses on a chain.
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip44::{Account, Purpose, CoinType, AddressIterator};
//! use khodpay_bip32::{ExtendedPrivateKey, Network};
//!
//! let seed = [0u8; 64];
//! let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
//! let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
//!
//! // Iterate over first 5 external addresses
//! let addresses: Vec<_> = AddressIterator::new_external(&account)
//!     .take(5)
//!     .collect();
//!
//! assert_eq!(addresses.len(), 5);
//! ```

use crate::{Account, Chain};
use khodpay_bip32::ExtendedPrivateKey;

/// Iterator for sequential address generation on a chain.
///
/// This iterator generates addresses sequentially starting from a given index.
/// It can be used for both external (receiving) and internal (change) chains.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::{Account, Purpose, CoinType, AddressIterator};
/// use khodpay_bip32::{ExtendedPrivateKey, Network};
///
/// let seed = [0u8; 64];
/// let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
/// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
///
/// // Create iterator for external chain
/// let mut iter = AddressIterator::new_external(&account);
///
/// // Get first address
/// let addr0 = iter.next().unwrap().unwrap();
/// assert_eq!(addr0.depth(), 5);
/// ```
#[derive(Debug)]
pub struct AddressIterator<'a> {
    account: &'a Account,
    chain: Chain,
    current_index: u32,
    max_index: Option<u32>,
}

impl<'a> AddressIterator<'a> {
    /// Creates a new iterator for the external (receiving) chain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, AddressIterator};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network};
    ///
    /// let seed = [0u8; 64];
    /// let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    ///
    /// let iter = AddressIterator::new_external(&account);
    /// ```
    pub fn new_external(account: &'a Account) -> Self {
        Self {
            account,
            chain: Chain::External,
            current_index: 0,
            max_index: None,
        }
    }

    /// Creates a new iterator for the internal (change) chain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, AddressIterator};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network};
    ///
    /// let seed = [0u8; 64];
    /// let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    ///
    /// let iter = AddressIterator::new_internal(&account);
    /// ```
    pub fn new_internal(account: &'a Account) -> Self {
        Self {
            account,
            chain: Chain::Internal,
            current_index: 0,
            max_index: None,
        }
    }

    /// Creates a new iterator for a specific chain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, AddressIterator};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network};
    ///
    /// let seed = [0u8; 64];
    /// let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    ///
    /// let iter = AddressIterator::new(&account, Chain::External);
    /// ```
    pub fn new(account: &'a Account, chain: Chain) -> Self {
        Self {
            account,
            chain,
            current_index: 0,
            max_index: None,
        }
    }

    /// Sets the starting index for the iterator.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, AddressIterator};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network};
    ///
    /// let seed = [0u8; 64];
    /// let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    ///
    /// // Start from index 10
    /// let iter = AddressIterator::new_external(&account).start_at(10);
    /// ```
    pub fn start_at(mut self, index: u32) -> Self {
        self.current_index = index;
        self
    }

    /// Sets the maximum index (inclusive) for the iterator.
    ///
    /// This creates a bounded iterator that stops after reaching the max index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, AddressIterator};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network};
    ///
    /// let seed = [0u8; 64];
    /// let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    ///
    /// // Only generate addresses 0-9
    /// let addresses: Vec<_> = AddressIterator::new_external(&account)
    ///     .max_index(9)
    ///     .collect();
    ///
    /// assert_eq!(addresses.len(), 10);
    /// ```
    pub fn max_index(mut self, max: u32) -> Self {
        self.max_index = Some(max);
        self
    }

    /// Returns the current index of the iterator.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, AddressIterator};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network};
    ///
    /// let seed = [0u8; 64];
    /// let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    ///
    /// let mut iter = AddressIterator::new_external(&account);
    /// assert_eq!(iter.current_index(), 0);
    ///
    /// iter.next();
    /// assert_eq!(iter.current_index(), 1);
    /// ```
    pub fn current_index(&self) -> u32 {
        self.current_index
    }

    /// Returns the chain being iterated.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Account, Purpose, CoinType, Chain, AddressIterator};
    /// use khodpay_bip32::{ExtendedPrivateKey, Network};
    ///
    /// let seed = [0u8; 64];
    /// let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    /// let account = Account::from_extended_key(master_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    ///
    /// let iter = AddressIterator::new_external(&account);
    /// assert_eq!(iter.get_chain(), Chain::External);
    /// ```
    pub fn get_chain(&self) -> Chain {
        self.chain
    }
}

impl<'a> Iterator for AddressIterator<'a> {
    type Item = crate::Result<ExtendedPrivateKey>;

    fn next(&mut self) -> Option<Self::Item> {
        // Check if we've reached the max index
        if let Some(max) = self.max_index {
            if self.current_index > max {
                return None;
            }
        }

        // Check for overflow
        let index = self.current_index;
        self.current_index = self.current_index.checked_add(1)?;

        // Derive the address
        let result = match self.chain {
            Chain::External => self.account.derive_external(index),
            Chain::Internal => self.account.derive_internal(index),
        };

        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoinType, Purpose};
    use khodpay_bip32::{ExtendedPrivateKey, Network};

    fn create_test_account() -> Account {
        let seed = [0u8; 64];
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive to account level: m/44'/0'/0'
        use khodpay_bip32::ChildNumber;
        let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
        let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
        let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
        
        Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0)
    }

    #[test]
    fn test_iterator_new_external() {
        let account = create_test_account();
        let iter = AddressIterator::new_external(&account);

        assert_eq!(iter.get_chain(), Chain::External);
        assert_eq!(iter.current_index(), 0);
    }

    #[test]
    fn test_iterator_new_internal() {
        let account = create_test_account();
        let iter = AddressIterator::new_internal(&account);

        assert_eq!(iter.get_chain(), Chain::Internal);
        assert_eq!(iter.current_index(), 0);
    }

    #[test]
    fn test_iterator_new_with_chain() {
        let account = create_test_account();
        let iter = AddressIterator::new(&account, Chain::External);

        assert_eq!(iter.get_chain(), Chain::External);
    }

    #[test]
    fn test_iterator_take() {
        let account = create_test_account();
        let addresses: Vec<_> = AddressIterator::new_external(&account)
            .take(5)
            .collect();

        assert_eq!(addresses.len(), 5);
        for addr in addresses {
            assert!(addr.is_ok());
        }
    }

    #[test]
    fn test_iterator_start_at() {
        let account = create_test_account();
        let mut iter = AddressIterator::new_external(&account).start_at(10);

        assert_eq!(iter.current_index(), 10);
        
        let addr = iter.next().unwrap().unwrap();
        assert_eq!(addr.depth(), 5);
        assert_eq!(iter.current_index(), 11);
    }

    #[test]
    fn test_iterator_max_index() {
        let account = create_test_account();
        let addresses: Vec<_> = AddressIterator::new_external(&account)
            .max_index(4)
            .collect();

        assert_eq!(addresses.len(), 5); // 0, 1, 2, 3, 4
    }

    #[test]
    fn test_iterator_bounded() {
        let account = create_test_account();
        let addresses: Vec<_> = AddressIterator::new_external(&account)
            .start_at(5)
            .max_index(9)
            .collect();

        assert_eq!(addresses.len(), 5); // 5, 6, 7, 8, 9
    }

    #[test]
    fn test_iterator_internal_chain() {
        let account = create_test_account();
        let addresses: Vec<_> = AddressIterator::new_internal(&account)
            .take(3)
            .collect();

        assert_eq!(addresses.len(), 3);
        for addr in addresses {
            assert!(addr.is_ok());
        }
    }

    #[test]
    fn test_iterator_sequential_indices() {
        let account = create_test_account();
        let mut iter = AddressIterator::new_external(&account);

        assert_eq!(iter.current_index(), 0);
        iter.next();
        assert_eq!(iter.current_index(), 1);
        iter.next();
        assert_eq!(iter.current_index(), 2);
    }

    #[test]
    fn test_iterator_collect() {
        let account = create_test_account();
        let addresses: Result<Vec<_>, _> = AddressIterator::new_external(&account)
            .take(10)
            .collect();

        assert!(addresses.is_ok());
        assert_eq!(addresses.unwrap().len(), 10);
    }

    #[test]
    fn test_iterator_enumerate() {
        let account = create_test_account();
        let addresses: Vec<_> = AddressIterator::new_external(&account)
            .take(5)
            .enumerate()
            .collect();

        assert_eq!(addresses.len(), 5);
        for (i, _) in addresses {
            assert!(i < 5);
        }
    }

    #[test]
    fn test_iterator_filter_map() {
        let account = create_test_account();
        let addresses: Vec<_> = AddressIterator::new_external(&account)
            .take(10)
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(addresses.len(), 10);
    }

    #[test]
    fn test_iterator_get_chain_method() {
        let account = create_test_account();
        let iter = AddressIterator::new_external(&account);

        assert_eq!(iter.get_chain(), Chain::External);
    }

    #[test]
    fn test_iterator_max_index_zero() {
        let account = create_test_account();
        let addresses: Vec<_> = AddressIterator::new_external(&account)
            .max_index(0)
            .collect();

        assert_eq!(addresses.len(), 1); // Only index 0
    }

    #[test]
    fn test_iterator_start_at_with_max() {
        let account = create_test_account();
        let addresses: Vec<_> = AddressIterator::new_external(&account)
            .start_at(100)
            .max_index(102)
            .collect();

        assert_eq!(addresses.len(), 3); // 100, 101, 102
    }

    #[test]
    fn test_iterator_large_range() {
        let account = create_test_account();
        let addresses: Vec<_> = AddressIterator::new_external(&account)
            .take(1000)
            .collect();

        assert_eq!(addresses.len(), 1000);
    }
}
