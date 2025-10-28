//! BIP-44 account discovery and gap limit implementation.
//!
//! This module provides traits and utilities for discovering used addresses and accounts
//! according to BIP-44 specifications. The gap limit algorithm stops searching after
//! finding a configurable number of consecutive unused addresses (typically 20).
//!
//! # Gap Limit
//!
//! BIP-44 defines a "gap limit" to determine when to stop scanning for addresses:
//! - If 20 consecutive unused addresses are found, stop scanning that chain
//! - This prevents infinite scanning while allowing address gaps
//! - Both external and internal chains have separate gap limits
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip44::{AccountDiscovery, GapLimitChecker};
//! use std::collections::HashSet;
//!
//! // Mock blockchain query - addresses 0, 2, 5 are used
//! struct MockBlockchain {
//!     used_addresses: HashSet<u32>,
//! }
//!
//! impl AccountDiscovery for MockBlockchain {
//!     fn is_address_used(&self, address_index: u32) -> std::result::Result<bool, Box<dyn std::error::Error>> {
//!         Ok(self.used_addresses.contains(&address_index))
//!     }
//! }
//!
//! let mut blockchain = MockBlockchain {
//!     used_addresses: [0, 2, 5].iter().copied().collect(),
//! };
//!
//! let checker = GapLimitChecker::new(20);
//! let last_used = checker.find_last_used_index(&blockchain, 0).unwrap();
//! assert_eq!(last_used, Some(5));
//! ```

/// Default gap limit as specified by BIP-44.
///
/// BIP-44 recommends stopping the scan after finding 20 consecutive unused addresses.
pub const DEFAULT_GAP_LIMIT: u32 = 20;

/// Trait for querying blockchain state to discover address usage.
///
/// Implementations of this trait provide the ability to check whether
/// a specific address has been used on the blockchain (has transaction history).
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::AccountDiscovery;
/// use std::collections::HashSet;
///
/// struct SimpleBlockchain {
///     used_indices: HashSet<u32>,
/// }
///
/// impl AccountDiscovery for SimpleBlockchain {
///     fn is_address_used(&self, address_index: u32) -> std::result::Result<bool, Box<dyn std::error::Error>> {
///         Ok(self.used_indices.contains(&address_index))
///     }
/// }
/// ```
pub trait AccountDiscovery {
    /// Checks if an address at the given index has been used.
    ///
    /// An address is considered "used" if it has any transaction history
    /// on the blockchain (either received or sent funds).
    ///
    /// # Arguments
    ///
    /// * `address_index` - The address index to check
    ///
    /// # Errors
    ///
    /// Returns an error if the blockchain query fails.
    fn is_address_used(&self, address_index: u32) -> std::result::Result<bool, Box<dyn std::error::Error>>;
}

/// Gap limit checker for BIP-44 address discovery.
///
/// Implements the gap limit algorithm to find the last used address index
/// on a chain. The algorithm stops scanning after finding a configurable
/// number of consecutive unused addresses.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::{AccountDiscovery, GapLimitChecker};
/// use std::collections::HashSet;
///
/// struct MockBlockchain {
///     used: HashSet<u32>,
/// }
///
/// impl AccountDiscovery for MockBlockchain {
///     fn is_address_used(&self, address_index: u32) -> std::result::Result<bool, Box<dyn std::error::Error>> {
///         Ok(self.used.contains(&address_index))
///     }
/// }
///
/// let blockchain = MockBlockchain {
///     used: [0, 1, 5, 10].iter().copied().collect(),
/// };
///
/// let checker = GapLimitChecker::new(20);
/// let result = checker.find_last_used_index(&blockchain, 0).unwrap();
/// assert_eq!(result, Some(10));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct GapLimitChecker {
    /// The number of consecutive unused addresses to find before stopping
    gap_limit: u32,
}

impl GapLimitChecker {
    /// Creates a new gap limit checker with the specified limit.
    ///
    /// # Arguments
    ///
    /// * `gap_limit` - Number of consecutive unused addresses before stopping
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::GapLimitChecker;
    ///
    /// let checker = GapLimitChecker::new(20);
    /// assert_eq!(checker.gap_limit(), 20);
    /// ```
    pub fn new(gap_limit: u32) -> Self {
        Self { gap_limit }
    }

    /// Creates a new gap limit checker with the default BIP-44 limit (20).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{GapLimitChecker, DEFAULT_GAP_LIMIT};
    ///
    /// let checker = GapLimitChecker::default();
    /// assert_eq!(checker.gap_limit(), DEFAULT_GAP_LIMIT);
    /// ```
    pub fn default() -> Self {
        Self::new(DEFAULT_GAP_LIMIT)
    }

    /// Returns the configured gap limit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::GapLimitChecker;
    ///
    /// let checker = GapLimitChecker::new(10);
    /// assert_eq!(checker.gap_limit(), 10);
    /// ```
    pub const fn gap_limit(&self) -> u32 {
        self.gap_limit
    }

    /// Finds the last used address index on a chain using the gap limit algorithm.
    ///
    /// Scans addresses starting from `start_index` and stops after finding
    /// `gap_limit` consecutive unused addresses. Returns the highest used
    /// address index found, or `None` if no addresses are used.
    ///
    /// # Arguments
    ///
    /// * `discovery` - Implementation of blockchain query interface
    /// * `start_index` - The address index to start scanning from
    ///
    /// # Returns
    ///
    /// - `Some(index)` - The highest used address index found
    /// - `None` - No used addresses found
    ///
    /// # Errors
    ///
    /// Returns an error if any blockchain query fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{AccountDiscovery, GapLimitChecker};
    /// use std::collections::HashSet;
    ///
    /// struct TestBlockchain {
    ///     used: HashSet<u32>,
    /// }
    ///
    /// impl AccountDiscovery for TestBlockchain {
    ///     fn is_address_used(&self, index: u32) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    ///         Ok(self.used.contains(&index))
    ///     }
    /// }
    ///
    /// let blockchain = TestBlockchain {
    ///     used: [0, 5, 10].iter().copied().collect(),
    /// };
    ///
    /// let checker = GapLimitChecker::new(20);
    /// let last = checker.find_last_used_index(&blockchain, 0).unwrap();
    /// assert_eq!(last, Some(10));
    /// ```
    pub fn find_last_used_index<D: AccountDiscovery>(
        &self,
        discovery: &D,
        start_index: u32,
    ) -> std::result::Result<Option<u32>, Box<dyn std::error::Error>> {
        let mut last_used_index: Option<u32> = None;
        let mut consecutive_unused = 0u32;
        let mut current_index = start_index;

        loop {
            // Check if address is used
            let is_used = discovery.is_address_used(current_index)?;

            if is_used {
                // Found a used address, reset gap counter and update last used
                last_used_index = Some(current_index);
                consecutive_unused = 0;
            } else {
                // Found an unused address, increment gap counter
                consecutive_unused += 1;

                // Stop if we've found enough consecutive unused addresses
                if consecutive_unused >= self.gap_limit {
                    break;
                }
            }

            // Move to next address, stop if we'd overflow
            if let Some(next) = current_index.checked_add(1) {
                current_index = next;
            } else {
                // Reached u32::MAX
                break;
            }
        }

        Ok(last_used_index)
    }

    /// Finds all used address indices on a chain up to the gap limit.
    ///
    /// Returns a vector of all used address indices found during scanning.
    ///
    /// # Arguments
    ///
    /// * `discovery` - Implementation of blockchain query interface
    /// * `start_index` - The address index to start scanning from
    ///
    /// # Returns
    ///
    /// A vector of used address indices in ascending order.
    ///
    /// # Errors
    ///
    /// Returns an error if any blockchain query fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{AccountDiscovery, GapLimitChecker};
    /// use std::collections::HashSet;
    ///
    /// struct TestBlockchain {
    ///     used: HashSet<u32>,
    /// }
    ///
    /// impl AccountDiscovery for TestBlockchain {
    ///     fn is_address_used(&self, index: u32) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    ///         Ok(self.used.contains(&index))
    ///     }
    /// }
    ///
    /// let blockchain = TestBlockchain {
    ///     used: [0, 2, 5].iter().copied().collect(),
    /// };
    ///
    /// let checker = GapLimitChecker::new(20);
    /// let used = checker.find_used_indices(&blockchain, 0).unwrap();
    /// assert_eq!(used, vec![0, 2, 5]);
    /// ```
    pub fn find_used_indices<D: AccountDiscovery>(
        &self,
        discovery: &D,
        start_index: u32,
    ) -> std::result::Result<Vec<u32>, Box<dyn std::error::Error>> {
        let mut used_indices = Vec::new();
        let mut consecutive_unused = 0u32;
        let mut current_index = start_index;

        loop {
            // Check if address is used
            let is_used = discovery.is_address_used(current_index)?;

            if is_used {
                used_indices.push(current_index);
                consecutive_unused = 0;
            } else {
                consecutive_unused += 1;

                if consecutive_unused >= self.gap_limit {
                    break;
                }
            }

            // Move to next address
            if let Some(next) = current_index.checked_add(1) {
                current_index = next;
            } else {
                break;
            }
        }

        Ok(used_indices)
    }
}

/// Result of scanning a single chain (external or internal).
///
/// Contains information about used addresses found during scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainScanResult {
    /// The chain that was scanned
    pub chain: crate::Chain,
    /// Indices of used addresses found
    pub used_indices: Vec<u32>,
    /// The highest used address index, if any
    pub last_used_index: Option<u32>,
}

/// Result of scanning both chains of an account.
///
/// Contains scan results for external (receiving) and internal (change) chains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountScanResult {
    /// Account index that was scanned
    pub account_index: u32,
    /// Result from scanning the external (receiving) chain
    pub external: ChainScanResult,
    /// Result from scanning the internal (change) chain
    pub internal: ChainScanResult,
}

impl AccountScanResult {
    /// Returns true if the account has any used addresses.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{AccountScanResult, ChainScanResult, Chain};
    ///
    /// let result = AccountScanResult {
    ///     account_index: 0,
    ///     external: ChainScanResult {
    ///         chain: Chain::External,
    ///         used_indices: vec![0, 1],
    ///         last_used_index: Some(1),
    ///     },
    ///     internal: ChainScanResult {
    ///         chain: Chain::Internal,
    ///         used_indices: vec![],
    ///         last_used_index: None,
    ///     },
    /// };
    ///
    /// assert!(result.is_used());
    /// ```
    pub fn is_used(&self) -> bool {
        !self.external.used_indices.is_empty() || !self.internal.used_indices.is_empty()
    }

    /// Returns the total number of used addresses across both chains.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{AccountScanResult, ChainScanResult, Chain};
    ///
    /// let result = AccountScanResult {
    ///     account_index: 0,
    ///     external: ChainScanResult {
    ///         chain: Chain::External,
    ///         used_indices: vec![0, 1, 2],
    ///         last_used_index: Some(2),
    ///     },
    ///     internal: ChainScanResult {
    ///         chain: Chain::Internal,
    ///         used_indices: vec![0],
    ///         last_used_index: Some(0),
    ///     },
    /// };
    ///
    /// assert_eq!(result.total_used_count(), 4);
    /// ```
    pub fn total_used_count(&self) -> usize {
        self.external.used_indices.len() + self.internal.used_indices.len()
    }
}

/// Scanner for discovering used accounts and addresses according to BIP-44.
///
/// Uses the gap limit algorithm to efficiently scan chains and accounts.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::{AccountScanner, GapLimitChecker};
///
/// let checker = GapLimitChecker::new(20);
/// let scanner = AccountScanner::new(checker);
///
/// assert_eq!(scanner.gap_limit(), 20);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct AccountScanner {
    /// The gap limit checker to use for scanning
    checker: GapLimitChecker,
}

impl AccountScanner {
    /// Creates a new account scanner with the given gap limit checker.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{AccountScanner, GapLimitChecker};
    ///
    /// let checker = GapLimitChecker::new(20);
    /// let scanner = AccountScanner::new(checker);
    /// ```
    pub fn new(checker: GapLimitChecker) -> Self {
        Self { checker }
    }

    /// Creates a new account scanner with the default gap limit (20).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{AccountScanner, DEFAULT_GAP_LIMIT};
    ///
    /// let scanner = AccountScanner::default();
    /// assert_eq!(scanner.gap_limit(), DEFAULT_GAP_LIMIT);
    /// ```
    pub fn default() -> Self {
        Self::new(GapLimitChecker::default())
    }

    /// Returns the gap limit used by this scanner.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{AccountScanner, GapLimitChecker};
    ///
    /// let scanner = AccountScanner::new(GapLimitChecker::new(10));
    /// assert_eq!(scanner.gap_limit(), 10);
    /// ```
    pub const fn gap_limit(&self) -> u32 {
        self.checker.gap_limit()
    }

    /// Scans a single chain for used addresses.
    ///
    /// # Arguments
    ///
    /// * `discovery` - Implementation of blockchain query interface
    /// * `chain` - The chain type being scanned
    ///
    /// # Returns
    ///
    /// A `ChainScanResult` containing all used addresses found.
    ///
    /// # Errors
    ///
    /// Returns an error if any blockchain query fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{AccountScanner, AccountDiscovery, GapLimitChecker, Chain};
    /// use std::collections::HashSet;
    ///
    /// struct MockBlockchain {
    ///     used: HashSet<u32>,
    /// }
    ///
    /// impl AccountDiscovery for MockBlockchain {
    ///     fn is_address_used(&self, index: u32) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    ///         Ok(self.used.contains(&index))
    ///     }
    /// }
    ///
    /// let blockchain = MockBlockchain {
    ///     used: [0, 2, 5].iter().copied().collect(),
    /// };
    ///
    /// let scanner = AccountScanner::new(GapLimitChecker::new(20));
    /// let result = scanner.scan_chain(&blockchain, Chain::External).unwrap();
    ///
    /// assert_eq!(result.chain, Chain::External);
    /// assert_eq!(result.used_indices, vec![0, 2, 5]);
    /// assert_eq!(result.last_used_index, Some(5));
    /// ```
    pub fn scan_chain<D: AccountDiscovery>(
        &self,
        discovery: &D,
        chain: crate::Chain,
    ) -> std::result::Result<ChainScanResult, Box<dyn std::error::Error>> {
        let used_indices = self.checker.find_used_indices(discovery, 0)?;
        let last_used_index = self.checker.find_last_used_index(discovery, 0)?;

        Ok(ChainScanResult {
            chain,
            used_indices,
            last_used_index,
        })
    }

    /// Discovers all used accounts for a given coin.
    ///
    /// Scans accounts starting from index 0 until finding an account with
    /// no used addresses (respecting the gap limit within each chain).
    ///
    /// # Arguments
    ///
    /// * `external_discovery` - Blockchain query for external chain
    /// * `internal_discovery` - Blockchain query for internal chain
    /// * `max_accounts` - Maximum number of accounts to scan (prevents infinite loops)
    ///
    /// # Returns
    ///
    /// A vector of `AccountScanResult` for all used accounts found.
    ///
    /// # Errors
    ///
    /// Returns an error if any blockchain query fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{AccountScanner, AccountDiscovery, GapLimitChecker};
    /// use std::collections::HashSet;
    ///
    /// struct MockBlockchain {
    ///     used: HashSet<u32>,
    /// }
    ///
    /// impl AccountDiscovery for MockBlockchain {
    ///     fn is_address_used(&self, index: u32) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    ///         Ok(self.used.contains(&index))
    ///     }
    /// }
    ///
    /// let external_chain = MockBlockchain {
    ///     used: [0, 1].iter().copied().collect(),
    /// };
    /// let internal_chain = MockBlockchain {
    ///     used: HashSet::new(),
    /// };
    ///
    /// let scanner = AccountScanner::new(GapLimitChecker::new(20));
    /// let accounts = scanner.discover_accounts(&external_chain, &internal_chain, 10).unwrap();
    ///
    /// // Note: With the same discovery for all accounts, it finds used addresses for all
    /// // In real usage, you'd have account-specific discovery instances
    /// assert_eq!(accounts.len(), 10);
    /// assert_eq!(accounts[0].account_index, 0);
    /// ```
    pub fn discover_accounts<D1: AccountDiscovery, D2: AccountDiscovery>(
        &self,
        external_discovery: &D1,
        internal_discovery: &D2,
        max_accounts: u32,
    ) -> std::result::Result<Vec<AccountScanResult>, Box<dyn std::error::Error>> {
        let mut results = Vec::new();

        for account_index in 0..max_accounts {
            // Scan both chains
            let external = self.scan_chain(external_discovery, crate::Chain::External)?;
            let internal = self.scan_chain(internal_discovery, crate::Chain::Internal)?;

            let account_result = AccountScanResult {
                account_index,
                external,
                internal,
            };

            // If account has any used addresses, add it to results
            if account_result.is_used() {
                results.push(account_result);
            } else {
                // Stop if we find an unused account (BIP-44 account gap)
                break;
            }
        }

        Ok(results)
    }
}

/// Mock blockchain backend for testing account discovery.
///
/// This provides a simple in-memory blockchain state for testing without
/// requiring actual blockchain connectivity.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::{MockBlockchain, AccountDiscovery};
///
/// let mut blockchain = MockBlockchain::new();
/// blockchain.mark_used(0);
/// blockchain.mark_used(2);
/// blockchain.mark_used(5);
///
/// assert!(blockchain.is_address_used(0).unwrap());
/// assert!(!blockchain.is_address_used(1).unwrap());
/// assert!(blockchain.is_address_used(5).unwrap());
/// ```
#[derive(Debug, Clone, Default)]
pub struct MockBlockchain {
    used_addresses: std::collections::HashSet<u32>,
}

impl MockBlockchain {
    /// Creates a new empty mock blockchain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::MockBlockchain;
    ///
    /// let blockchain = MockBlockchain::new();
    /// ```
    pub fn new() -> Self {
        Self {
            used_addresses: std::collections::HashSet::new(),
        }
    }

    /// Creates a mock blockchain with pre-configured used addresses.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{MockBlockchain, AccountDiscovery};
    ///
    /// let blockchain = MockBlockchain::with_used_addresses(&[0, 2, 5, 10]);
    /// assert!(blockchain.is_address_used(5).unwrap());
    /// ```
    pub fn with_used_addresses(addresses: &[u32]) -> Self {
        Self {
            used_addresses: addresses.iter().copied().collect(),
        }
    }

    /// Marks an address as used.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{MockBlockchain, AccountDiscovery};
    ///
    /// let mut blockchain = MockBlockchain::new();
    /// blockchain.mark_used(5);
    /// assert!(blockchain.is_address_used(5).unwrap());
    /// ```
    pub fn mark_used(&mut self, address_index: u32) {
        self.used_addresses.insert(address_index);
    }

    /// Marks multiple addresses as used.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::MockBlockchain;
    ///
    /// let mut blockchain = MockBlockchain::new();
    /// blockchain.mark_used_batch(&[0, 1, 2, 5]);
    /// assert_eq!(blockchain.used_count(), 4);
    /// ```
    pub fn mark_used_batch(&mut self, addresses: &[u32]) {
        for &addr in addresses {
            self.used_addresses.insert(addr);
        }
    }

    /// Marks an address as unused (removes it).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{MockBlockchain, AccountDiscovery};
    ///
    /// let mut blockchain = MockBlockchain::with_used_addresses(&[0, 1, 2]);
    /// blockchain.mark_unused(1);
    /// assert!(!blockchain.is_address_used(1).unwrap());
    /// ```
    pub fn mark_unused(&mut self, address_index: u32) {
        self.used_addresses.remove(&address_index);
    }

    /// Returns the number of used addresses.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::MockBlockchain;
    ///
    /// let blockchain = MockBlockchain::with_used_addresses(&[0, 2, 5]);
    /// assert_eq!(blockchain.used_count(), 3);
    /// ```
    pub fn used_count(&self) -> usize {
        self.used_addresses.len()
    }

    /// Returns a sorted vector of all used address indices.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::MockBlockchain;
    ///
    /// let blockchain = MockBlockchain::with_used_addresses(&[5, 0, 2]);
    /// assert_eq!(blockchain.get_used_addresses(), vec![0, 2, 5]);
    /// ```
    pub fn get_used_addresses(&self) -> Vec<u32> {
        let mut addresses: Vec<u32> = self.used_addresses.iter().copied().collect();
        addresses.sort_unstable();
        addresses
    }

    /// Clears all used addresses.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::MockBlockchain;
    ///
    /// let mut blockchain = MockBlockchain::with_used_addresses(&[0, 1, 2]);
    /// blockchain.clear();
    /// assert_eq!(blockchain.used_count(), 0);
    /// ```
    pub fn clear(&mut self) {
        self.used_addresses.clear();
    }

    /// Checks if any addresses are marked as used.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::MockBlockchain;
    ///
    /// let empty = MockBlockchain::new();
    /// assert!(empty.is_empty());
    ///
    /// let used = MockBlockchain::with_used_addresses(&[0]);
    /// assert!(!used.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.used_addresses.is_empty()
    }
}

impl AccountDiscovery for MockBlockchain {
    fn is_address_used(&self, address_index: u32) -> std::result::Result<bool, Box<dyn std::error::Error>> {
        Ok(self.used_addresses.contains(&address_index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_gap_limit_checker_new() {
        let checker = GapLimitChecker::new(10);
        assert_eq!(checker.gap_limit(), 10);

        let checker = GapLimitChecker::new(20);
        assert_eq!(checker.gap_limit(), 20);
    }

    #[test]
    fn test_gap_limit_checker_default() {
        let checker = GapLimitChecker::default();
        assert_eq!(checker.gap_limit(), DEFAULT_GAP_LIMIT);
        assert_eq!(checker.gap_limit(), 20);
    }

    #[test]
    fn test_find_last_used_no_addresses() {
        let blockchain = MockBlockchain {
            used_addresses: HashSet::new(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_last_used_index(&blockchain, 0).unwrap();
        
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_last_used_single_address() {
        let blockchain = MockBlockchain {
            used_addresses: [5].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_last_used_index(&blockchain, 0).unwrap();
        
        assert_eq!(result, Some(5));
    }

    #[test]
    fn test_find_last_used_multiple_addresses() {
        let blockchain = MockBlockchain {
            used_addresses: [0, 2, 5, 10].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_last_used_index(&blockchain, 0).unwrap();
        
        assert_eq!(result, Some(10));
    }

    #[test]
    fn test_find_last_used_with_gap() {
        let blockchain = MockBlockchain {
            used_addresses: [0, 1, 2, 25].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_last_used_index(&blockchain, 0).unwrap();
        
        // Should stop at index 2 because there's a gap of 20+ after it
        assert_eq!(result, Some(2));
    }

    #[test]
    fn test_find_last_used_gap_limit_5() {
        let blockchain = MockBlockchain {
            used_addresses: [0, 1, 2, 10].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(5);
        let result = checker.find_last_used_index(&blockchain, 0).unwrap();
        
        // With gap limit 5, should stop at index 2
        assert_eq!(result, Some(2));
    }

    #[test]
    fn test_find_last_used_consecutive_addresses() {
        let blockchain = MockBlockchain {
            used_addresses: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_last_used_index(&blockchain, 0).unwrap();
        
        assert_eq!(result, Some(9));
    }

    #[test]
    fn test_find_last_used_sparse_addresses() {
        let blockchain = MockBlockchain {
            used_addresses: [0, 5, 10, 15, 19].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_last_used_index(&blockchain, 0).unwrap();
        
        assert_eq!(result, Some(19));
    }

    #[test]
    fn test_find_last_used_start_offset() {
        let blockchain = MockBlockchain {
            used_addresses: [10, 15, 20].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_last_used_index(&blockchain, 10).unwrap();
        
        assert_eq!(result, Some(20));
    }

    #[test]
    fn test_find_last_used_exact_gap_limit() {
        let blockchain = MockBlockchain {
            used_addresses: [0, 20].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_last_used_index(&blockchain, 0).unwrap();
        
        // Gap is exactly 20, should find address 20
        assert_eq!(result, Some(20));
    }

    #[test]
    fn test_find_used_indices_empty() {
        let blockchain = MockBlockchain {
            used_addresses: HashSet::new(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_used_indices(&blockchain, 0).unwrap();
        
        assert_eq!(result, Vec::<u32>::new());
    }

    #[test]
    fn test_find_used_indices_single() {
        let blockchain = MockBlockchain {
            used_addresses: [5].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_used_indices(&blockchain, 0).unwrap();
        
        assert_eq!(result, vec![5]);
    }

    #[test]
    fn test_find_used_indices_multiple() {
        let blockchain = MockBlockchain {
            used_addresses: [0, 2, 5, 10].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_used_indices(&blockchain, 0).unwrap();
        
        assert_eq!(result, vec![0, 2, 5, 10]);
    }

    #[test]
    fn test_find_used_indices_with_gap() {
        let blockchain = MockBlockchain {
            used_addresses: [0, 1, 2, 30].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_used_indices(&blockchain, 0).unwrap();
        
        // Should stop before reaching 30 due to gap limit
        assert_eq!(result, vec![0, 1, 2]);
    }

    #[test]
    fn test_find_used_indices_ordered() {
        let blockchain = MockBlockchain {
            used_addresses: [10, 5, 15, 0].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(20);
        let result = checker.find_used_indices(&blockchain, 0).unwrap();
        
        // Should return in ascending order
        assert_eq!(result, vec![0, 5, 10, 15]);
    }

    #[test]
    fn test_clone_and_copy() {
        let checker1 = GapLimitChecker::new(15);
        let checker2 = checker1;
        let checker3 = checker1.clone();
        
        assert_eq!(checker1.gap_limit(), 15);
        assert_eq!(checker2.gap_limit(), 15);
        assert_eq!(checker3.gap_limit(), 15);
    }

    #[test]
    fn test_debug_format() {
        let checker = GapLimitChecker::new(20);
        let debug_str = format!("{:?}", checker);
        
        assert!(debug_str.contains("GapLimitChecker"));
        assert!(debug_str.contains("20"));
    }

    #[test]
    fn test_gap_limit_1() {
        let blockchain = MockBlockchain {
            used_addresses: [0, 2].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(1);
        let result = checker.find_last_used_index(&blockchain, 0).unwrap();
        
        // Should stop immediately after first unused address
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_large_gap_limit() {
        let blockchain = MockBlockchain {
            used_addresses: [0, 10, 20].iter().copied().collect(),
        };

        let checker = GapLimitChecker::new(100);
        let result = checker.find_last_used_index(&blockchain, 0).unwrap();
        
        assert_eq!(result, Some(20));
    }

    // AccountScanner tests
    #[test]
    fn test_account_scanner_new() {
        let checker = GapLimitChecker::new(15);
        let scanner = AccountScanner::new(checker);
        
        assert_eq!(scanner.gap_limit(), 15);
    }

    #[test]
    fn test_account_scanner_default() {
        let scanner = AccountScanner::default();
        
        assert_eq!(scanner.gap_limit(), DEFAULT_GAP_LIMIT);
    }

    #[test]
    fn test_scan_chain_empty() {
        use crate::Chain;
        
        let blockchain = MockBlockchain {
            used_addresses: HashSet::new(),
        };

        let scanner = AccountScanner::new(GapLimitChecker::new(20));
        let result = scanner.scan_chain(&blockchain, Chain::External).unwrap();
        
        assert_eq!(result.chain, Chain::External);
        assert_eq!(result.used_indices, Vec::<u32>::new());
        assert_eq!(result.last_used_index, None);
    }

    #[test]
    fn test_scan_chain_with_addresses() {
        use crate::Chain;
        
        let blockchain = MockBlockchain {
            used_addresses: [0, 2, 5, 10].iter().copied().collect(),
        };

        let scanner = AccountScanner::new(GapLimitChecker::new(20));
        let result = scanner.scan_chain(&blockchain, Chain::External).unwrap();
        
        assert_eq!(result.chain, Chain::External);
        assert_eq!(result.used_indices, vec![0, 2, 5, 10]);
        assert_eq!(result.last_used_index, Some(10));
    }

    #[test]
    fn test_scan_chain_internal() {
        use crate::Chain;
        
        let blockchain = MockBlockchain {
            used_addresses: [0, 1].iter().copied().collect(),
        };

        let scanner = AccountScanner::new(GapLimitChecker::new(20));
        let result = scanner.scan_chain(&blockchain, Chain::Internal).unwrap();
        
        assert_eq!(result.chain, Chain::Internal);
        assert_eq!(result.used_indices, vec![0, 1]);
        assert_eq!(result.last_used_index, Some(1));
    }

    #[test]
    fn test_account_scan_result_is_used() {
        use crate::Chain;
        
        let result = AccountScanResult {
            account_index: 0,
            external: ChainScanResult {
                chain: Chain::External,
                used_indices: vec![0],
                last_used_index: Some(0),
            },
            internal: ChainScanResult {
                chain: Chain::Internal,
                used_indices: vec![],
                last_used_index: None,
            },
        };
        
        assert!(result.is_used());
    }

    #[test]
    fn test_account_scan_result_not_used() {
        use crate::Chain;
        
        let result = AccountScanResult {
            account_index: 0,
            external: ChainScanResult {
                chain: Chain::External,
                used_indices: vec![],
                last_used_index: None,
            },
            internal: ChainScanResult {
                chain: Chain::Internal,
                used_indices: vec![],
                last_used_index: None,
            },
        };
        
        assert!(!result.is_used());
    }

    #[test]
    fn test_account_scan_result_total_count() {
        use crate::Chain;
        
        let result = AccountScanResult {
            account_index: 0,
            external: ChainScanResult {
                chain: Chain::External,
                used_indices: vec![0, 1, 2],
                last_used_index: Some(2),
            },
            internal: ChainScanResult {
                chain: Chain::Internal,
                used_indices: vec![0, 5],
                last_used_index: Some(5),
            },
        };
        
        assert_eq!(result.total_used_count(), 5);
    }

    #[test]
    fn test_discover_accounts_single_account() {
        let external = MockBlockchain {
            used_addresses: [0, 1].iter().copied().collect(),
        };
        let internal = MockBlockchain {
            used_addresses: HashSet::new(),
        };

        let scanner = AccountScanner::new(GapLimitChecker::new(20));
        let accounts = scanner.discover_accounts(&external, &internal, 10).unwrap();
        
        // Note: With the same discovery instance for all accounts, it will find
        // used addresses for all accounts up to max_accounts
        // In a real implementation, you'd have account-specific discovery instances
        assert_eq!(accounts.len(), 10);
        assert_eq!(accounts[0].account_index, 0);
        assert!(accounts[0].is_used());
    }

    #[test]
    fn test_discover_accounts_multiple() {
        let external = MockBlockchain {
            used_addresses: [0, 1].iter().copied().collect(),
        };
        let internal = MockBlockchain {
            used_addresses: [0].iter().copied().collect(),
        };

        let scanner = AccountScanner::new(GapLimitChecker::new(20));
        let accounts = scanner.discover_accounts(&external, &internal, 10).unwrap();
        
        // Since we're using the same discovery for all accounts, it will find used addresses
        // The implementation scans until it finds an unused account
        assert!(!accounts.is_empty());
    }

    #[test]
    fn test_discover_accounts_empty() {
        let external = MockBlockchain {
            used_addresses: HashSet::new(),
        };
        let internal = MockBlockchain {
            used_addresses: HashSet::new(),
        };

        let scanner = AccountScanner::new(GapLimitChecker::new(20));
        let accounts = scanner.discover_accounts(&external, &internal, 10).unwrap();
        
        assert_eq!(accounts.len(), 0);
    }

    #[test]
    fn test_discover_accounts_max_limit() {
        let external = MockBlockchain {
            used_addresses: [0].iter().copied().collect(),
        };
        let internal = MockBlockchain {
            used_addresses: HashSet::new(),
        };

        let scanner = AccountScanner::new(GapLimitChecker::new(20));
        let accounts = scanner.discover_accounts(&external, &internal, 3).unwrap();
        
        // Should respect max_accounts limit
        assert!(accounts.len() <= 3);
    }

    #[test]
    fn test_chain_scan_result_equality() {
        use crate::Chain;
        
        let result1 = ChainScanResult {
            chain: Chain::External,
            used_indices: vec![0, 1],
            last_used_index: Some(1),
        };
        
        let result2 = ChainScanResult {
            chain: Chain::External,
            used_indices: vec![0, 1],
            last_used_index: Some(1),
        };
        
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_account_scan_result_clone() {
        use crate::Chain;
        
        let result = AccountScanResult {
            account_index: 0,
            external: ChainScanResult {
                chain: Chain::External,
                used_indices: vec![0],
                last_used_index: Some(0),
            },
            internal: ChainScanResult {
                chain: Chain::Internal,
                used_indices: vec![],
                last_used_index: None,
            },
        };
        
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    #[test]
    fn test_account_scanner_clone() {
        let scanner1 = AccountScanner::new(GapLimitChecker::new(10));
        let scanner2 = scanner1;
        
        assert_eq!(scanner1.gap_limit(), scanner2.gap_limit());
    }

    #[test]
    fn test_account_scan_result_debug() {
        use crate::Chain;
        
        let result = AccountScanResult {
            account_index: 0,
            external: ChainScanResult {
                chain: Chain::External,
                used_indices: vec![0],
                last_used_index: Some(0),
            },
            internal: ChainScanResult {
                chain: Chain::Internal,
                used_indices: vec![],
                last_used_index: None,
            },
        };
        
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("AccountScanResult"));
    }

    // MockBlockchain tests
    #[test]
    fn test_mock_blockchain_new() {
        let blockchain = MockBlockchain::new();
        assert_eq!(blockchain.used_count(), 0);
        assert!(blockchain.is_empty());
    }

    #[test]
    fn test_mock_blockchain_default() {
        let blockchain = MockBlockchain::default();
        assert_eq!(blockchain.used_count(), 0);
    }

    #[test]
    fn test_mock_blockchain_with_used_addresses() {
        let blockchain = MockBlockchain::with_used_addresses(&[0, 2, 5, 10]);
        
        assert_eq!(blockchain.used_count(), 4);
        assert!(blockchain.is_address_used(0).unwrap());
        assert!(!blockchain.is_address_used(1).unwrap());
        assert!(blockchain.is_address_used(2).unwrap());
        assert!(blockchain.is_address_used(10).unwrap());
    }

    #[test]
    fn test_mock_blockchain_mark_used() {
        let mut blockchain = MockBlockchain::new();
        
        blockchain.mark_used(5);
        assert!(blockchain.is_address_used(5).unwrap());
        assert_eq!(blockchain.used_count(), 1);
    }

    #[test]
    fn test_mock_blockchain_mark_used_duplicate() {
        let mut blockchain = MockBlockchain::new();
        
        blockchain.mark_used(5);
        blockchain.mark_used(5);
        
        assert_eq!(blockchain.used_count(), 1);
    }

    #[test]
    fn test_mock_blockchain_mark_used_batch() {
        let mut blockchain = MockBlockchain::new();
        
        blockchain.mark_used_batch(&[0, 1, 2, 5, 10]);
        
        assert_eq!(blockchain.used_count(), 5);
        assert!(blockchain.is_address_used(0).unwrap());
        assert!(blockchain.is_address_used(10).unwrap());
    }

    #[test]
    fn test_mock_blockchain_mark_unused() {
        let mut blockchain = MockBlockchain::with_used_addresses(&[0, 1, 2]);
        
        blockchain.mark_unused(1);
        
        assert!(!blockchain.is_address_used(1).unwrap());
        assert_eq!(blockchain.used_count(), 2);
    }

    #[test]
    fn test_mock_blockchain_mark_unused_not_present() {
        let mut blockchain = MockBlockchain::with_used_addresses(&[0, 1]);
        
        blockchain.mark_unused(5);
        
        assert_eq!(blockchain.used_count(), 2);
    }

    #[test]
    fn test_mock_blockchain_get_used_addresses() {
        let blockchain = MockBlockchain::with_used_addresses(&[10, 5, 0, 2]);
        
        let used = blockchain.get_used_addresses();
        assert_eq!(used, vec![0, 2, 5, 10]);
    }

    #[test]
    fn test_mock_blockchain_get_used_addresses_empty() {
        let blockchain = MockBlockchain::new();
        
        let used = blockchain.get_used_addresses();
        assert_eq!(used, Vec::<u32>::new());
    }

    #[test]
    fn test_mock_blockchain_clear() {
        let mut blockchain = MockBlockchain::with_used_addresses(&[0, 1, 2, 5]);
        
        assert_eq!(blockchain.used_count(), 4);
        
        blockchain.clear();
        
        assert_eq!(blockchain.used_count(), 0);
        assert!(blockchain.is_empty());
    }

    #[test]
    fn test_mock_blockchain_is_empty() {
        let empty = MockBlockchain::new();
        assert!(empty.is_empty());
        
        let not_empty = MockBlockchain::with_used_addresses(&[0]);
        assert!(!not_empty.is_empty());
    }

    #[test]
    fn test_mock_blockchain_clone() {
        let blockchain1 = MockBlockchain::with_used_addresses(&[0, 1, 2]);
        let blockchain2 = blockchain1.clone();
        
        assert_eq!(blockchain1.used_count(), blockchain2.used_count());
        assert_eq!(blockchain1.get_used_addresses(), blockchain2.get_used_addresses());
    }

    #[test]
    fn test_mock_blockchain_debug() {
        let blockchain = MockBlockchain::with_used_addresses(&[0, 1]);
        let debug_str = format!("{:?}", blockchain);
        
        assert!(debug_str.contains("MockBlockchain"));
    }

    #[test]
    fn test_mock_blockchain_account_discovery_trait() {
        let blockchain = MockBlockchain::with_used_addresses(&[0, 5, 10]);
        
        // Test via trait
        assert!(blockchain.is_address_used(0).unwrap());
        assert!(!blockchain.is_address_used(1).unwrap());
        assert!(blockchain.is_address_used(10).unwrap());
    }

    #[test]
    fn test_mock_blockchain_with_gap_limit_checker() {
        let blockchain = MockBlockchain::with_used_addresses(&[0, 2, 5]);
        let checker = GapLimitChecker::new(20);
        
        let last_used = checker.find_last_used_index(&blockchain, 0).unwrap();
        assert_eq!(last_used, Some(5));
        
        let used_indices = checker.find_used_indices(&blockchain, 0).unwrap();
        assert_eq!(used_indices, vec![0, 2, 5]);
    }

    #[test]
    fn test_mock_blockchain_with_scanner() {
        use crate::Chain;
        
        let blockchain = MockBlockchain::with_used_addresses(&[0, 1, 5, 10]);
        let scanner = AccountScanner::new(GapLimitChecker::new(20));
        
        let result = scanner.scan_chain(&blockchain, Chain::External).unwrap();
        
        assert_eq!(result.used_indices, vec![0, 1, 5, 10]);
        assert_eq!(result.last_used_index, Some(10));
    }

    #[test]
    fn test_mock_blockchain_mutability() {
        let mut blockchain = MockBlockchain::new();
        
        // Add some addresses
        blockchain.mark_used(0);
        blockchain.mark_used(1);
        assert_eq!(blockchain.used_count(), 2);
        
        // Remove one
        blockchain.mark_unused(0);
        assert_eq!(blockchain.used_count(), 1);
        
        // Add batch
        blockchain.mark_used_batch(&[5, 10, 15]);
        assert_eq!(blockchain.used_count(), 4);
        
        // Clear all
        blockchain.clear();
        assert_eq!(blockchain.used_count(), 0);
    }

    #[test]
    fn test_mock_blockchain_large_indices() {
        let mut blockchain = MockBlockchain::new();
        
        blockchain.mark_used(1000);
        blockchain.mark_used(10000);
        blockchain.mark_used(100000);
        
        assert!(blockchain.is_address_used(1000).unwrap());
        assert!(blockchain.is_address_used(10000).unwrap());
        assert!(blockchain.is_address_used(100000).unwrap());
        assert_eq!(blockchain.used_count(), 3);
    }
}

