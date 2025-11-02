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
use std::fmt;
use std::str::FromStr;

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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    /// Validates that this path conforms to BIP-44 rules.
    ///
    /// This method is informational since all `Bip44Path` instances are guaranteed
    /// to be valid through the constructor. However, it can be useful for
    /// documentation and explicit validation checks.
    ///
    /// # BIP-44 Rules
    ///
    /// - Path must have exactly 5 levels
    /// - Account index must be ≤ 2^31 - 1
    /// - All component values must be valid
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    /// assert!(path.is_valid());
    /// ```
    pub const fn is_valid(&self) -> bool {
        // All Bip44Path instances are valid by construction
        // Account validation is done in the constructor
        true
    }

    /// Returns the depth of this BIP-44 path.
    ///
    /// BIP-44 paths always have a depth of 5 levels.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    /// assert_eq!(path.depth(), 5);
    /// ```
    pub const fn depth(&self) -> u8 {
        5
    }

    /// Returns a new path with the address index incremented by 1.
    ///
    /// This is useful for generating sequential addresses on the same chain.
    /// If the address index is at `u32::MAX`, it wraps around to 0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    /// let next = path.next_address();
    ///
    /// assert_eq!(next.address_index(), 1);
    /// assert_eq!(next.chain(), Chain::External);
    /// assert_eq!(next.account(), 0);
    /// ```
    pub fn next_address(&self) -> Self {
        Self {
            purpose: self.purpose,
            coin_type: self.coin_type,
            account: self.account,
            chain: self.chain,
            address_index: self.address_index.wrapping_add(1),
        }
    }

    /// Returns a new path with the specified address index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    /// let addr_5 = path.with_address_index(5);
    ///
    /// assert_eq!(addr_5.address_index(), 5);
    /// ```
    pub fn with_address_index(&self, address_index: u32) -> Self {
        Self {
            purpose: self.purpose,
            coin_type: self.coin_type,
            account: self.account,
            chain: self.chain,
            address_index,
        }
    }

    /// Returns a new path with the specified chain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let external = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    /// let internal = external.with_chain(Chain::Internal);
    ///
    /// assert_eq!(internal.chain(), Chain::Internal);
    /// assert_eq!(internal.address_index(), 0);
    /// ```
    pub fn with_chain(&self, chain: Chain) -> Self {
        Self {
            purpose: self.purpose,
            coin_type: self.coin_type,
            account: self.account,
            chain,
            address_index: self.address_index,
        }
    }

    /// Returns a new path for the external (receiving) chain with the same address index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let change = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::Internal, 5).unwrap();
    /// let receive = change.to_external();
    ///
    /// assert_eq!(receive.chain(), Chain::External);
    /// assert_eq!(receive.address_index(), 5);
    /// ```
    pub fn to_external(&self) -> Self {
        self.with_chain(Chain::External)
    }

    /// Returns a new path for the internal (change) chain with the same address index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let receive = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 5).unwrap();
    /// let change = receive.to_internal();
    ///
    /// assert_eq!(change.chain(), Chain::Internal);
    /// assert_eq!(change.address_index(), 5);
    /// ```
    pub fn to_internal(&self) -> Self {
        self.with_chain(Chain::Internal)
    }

    /// Returns a new path with the specified account index.
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
    /// let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    /// let account_1 = path.with_account(1).unwrap();
    ///
    /// assert_eq!(account_1.account(), 1);
    /// ```
    pub fn with_account(&self, account: u32) -> Result<Self> {
        if account > MAX_HARDENED_INDEX {
            return Err(Error::InvalidAccount {
                reason: format!(
                    "Account index {} exceeds maximum hardened index {}",
                    account, MAX_HARDENED_INDEX
                ),
            });
        }

        Ok(Self {
            purpose: self.purpose,
            coin_type: self.coin_type,
            account,
            chain: self.chain,
            address_index: self.address_index,
        })
    }

    /// Returns a new path with the account incremented by 1.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAccount`] if incrementing would exceed 2^31 - 1.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    /// let next = path.next_account().unwrap();
    ///
    /// assert_eq!(next.account(), 1);
    /// ```
    pub fn next_account(&self) -> Result<Self> {
        let next_account = self
            .account
            .checked_add(1)
            .ok_or_else(|| Error::InvalidAccount {
                reason: format!(
                    "Cannot increment account beyond maximum value {}",
                    MAX_HARDENED_INDEX
                ),
            })?;

        self.with_account(next_account)
    }

    /// Returns a new path with the specified purpose.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let bip44 = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    /// let bip84 = bip44.with_purpose(Purpose::BIP84);
    ///
    /// assert_eq!(bip84.purpose(), Purpose::BIP84);
    /// ```
    pub fn with_purpose(&self, purpose: Purpose) -> Self {
        Self {
            purpose,
            coin_type: self.coin_type,
            account: self.account,
            chain: self.chain,
            address_index: self.address_index,
        }
    }

    /// Returns a new path with the specified coin type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let btc = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    /// let eth = btc.with_coin_type(CoinType::Ethereum);
    ///
    /// assert_eq!(eth.coin_type(), CoinType::Ethereum);
    /// ```
    pub fn with_coin_type(&self, coin_type: CoinType) -> Self {
        Self {
            purpose: self.purpose,
            coin_type,
            account: self.account,
            chain: self.chain,
            address_index: self.address_index,
        }
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

impl TryFrom<DerivationPath> for Bip44Path {
    type Error = Error;

    /// Attempts to convert a BIP-32 derivation path to a BIP-44 path.
    ///
    /// This validates that the derivation path follows BIP-44 rules:
    /// - Must have exactly 5 levels
    /// - First 3 levels must be hardened (purpose, coin_type, account)
    /// - Last 2 levels must be normal (chain, address_index)
    /// - Purpose must be valid (44, 49, 84, or 86)
    /// - Chain must be valid (0 or 1)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Path depth is not 5
    /// - Hardening is incorrect
    /// - Purpose or chain values are invalid
    /// - Account index is out of range
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    /// use khodpay_bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// // Valid BIP-44 path
    /// let derivation = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
    /// let bip44 = Bip44Path::try_from(derivation).unwrap();
    /// assert_eq!(bip44.purpose(), Purpose::BIP44);
    ///
    /// // Invalid: wrong depth
    /// let invalid = DerivationPath::from_str("m/44'/0'/0'").unwrap();
    /// assert!(Bip44Path::try_from(invalid).is_err());
    ///
    /// // Invalid: chain is hardened
    /// let invalid = DerivationPath::from_str("m/44'/0'/0'/0'/0").unwrap();
    /// assert!(Bip44Path::try_from(invalid).is_err());
    /// ```
    fn try_from(path: DerivationPath) -> Result<Self> {
        // Validate depth
        if path.depth() != 5 {
            return Err(Error::InvalidDepth {
                depth: path.depth() as usize,
            });
        }

        let children = path.as_slice();

        // Validate first 3 levels are hardened
        if !children[0].is_hardened() {
            return Err(Error::InvalidHardenedLevel {
                reason: "Purpose (level 0) must be hardened".to_string(),
            });
        }
        if !children[1].is_hardened() {
            return Err(Error::InvalidHardenedLevel {
                reason: "Coin type (level 1) must be hardened".to_string(),
            });
        }
        if !children[2].is_hardened() {
            return Err(Error::InvalidHardenedLevel {
                reason: "Account (level 2) must be hardened".to_string(),
            });
        }

        // Validate last 2 levels are normal
        if children[3].is_hardened() {
            return Err(Error::InvalidHardenedLevel {
                reason: "Chain (level 3) must not be hardened".to_string(),
            });
        }
        if children[4].is_hardened() {
            return Err(Error::InvalidHardenedLevel {
                reason: "Address index (level 4) must not be hardened".to_string(),
            });
        }

        // Extract values (use .value() to get base index without hardening bit)
        let purpose_value = children[0].value();
        let coin_type_value = children[1].value();
        let account = children[2].value();
        let chain_value = children[3].value();
        let address_index = children[4].value();

        // Validate and convert types
        let purpose = Purpose::try_from(purpose_value)?;
        let coin_type = CoinType::try_from(coin_type_value)?;
        let chain = Chain::try_from(chain_value)?;

        // Create the path (this also validates account range)
        Bip44Path::new(purpose, coin_type, account, chain, address_index)
    }
}

impl TryFrom<&DerivationPath> for Bip44Path {
    type Error = Error;

    /// Attempts to convert a reference to a BIP-32 derivation path to a BIP-44 path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose};
    /// use khodpay_bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let derivation = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
    /// let bip44 = Bip44Path::try_from(&derivation).unwrap();
    /// assert_eq!(bip44.purpose(), Purpose::BIP44);
    /// ```
    fn try_from(path: &DerivationPath) -> Result<Self> {
        Bip44Path::try_from(path.clone())
    }
}

impl fmt::Display for Bip44Path {
    /// Formats the BIP-44 path using standard notation.
    ///
    /// The format follows BIP-44 notation: `m/purpose'/coin_type'/account'/chain/address_index`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    ///
    /// let path = Bip44Path::new(
    ///     Purpose::BIP44,
    ///     CoinType::Bitcoin,
    ///     0,
    ///     Chain::External,
    ///     0,
    /// ).unwrap();
    ///
    /// assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    ///
    /// let eth_path = Bip44Path::new(
    ///     Purpose::BIP44,
    ///     CoinType::Ethereum,
    ///     1,
    ///     Chain::Internal,
    ///     5,
    /// ).unwrap();
    ///
    /// assert_eq!(eth_path.to_string(), "m/44'/60'/1'/1/5");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "m/{}'/{}'/{}'/{}/{}",
            self.purpose.value(),
            self.coin_type.index(),
            self.account,
            self.chain.value(),
            self.address_index
        )
    }
}

impl FromStr for Bip44Path {
    type Err = Error;

    /// Parses a BIP-44 path from a string.
    ///
    /// The string must follow BIP-44 notation: `m/purpose'/coin_type'/account'/chain/address_index`
    ///
    /// # Rules
    ///
    /// - Must start with `m/`
    /// - Must have exactly 5 levels
    /// - First 3 levels (purpose, coin_type, account) must be hardened (marked with `'`)
    /// - Last 2 levels (chain, address_index) must be normal (no `'`)
    /// - All indices must be valid numbers
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path doesn't start with `m/`
    /// - The path doesn't have exactly 5 levels
    /// - Hardening is incorrect (first 3 must be hardened, last 2 must not be)
    /// - Any index is invalid or out of range
    /// - The purpose or chain value is not recognized
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{Bip44Path, Purpose, CoinType, Chain};
    /// use std::str::FromStr;
    ///
    /// // Valid Bitcoin path
    /// let path = Bip44Path::from_str("m/44'/0'/0'/0/0").unwrap();
    /// assert_eq!(path.purpose(), Purpose::BIP44);
    /// assert_eq!(path.coin_type(), CoinType::Bitcoin);
    ///
    /// // Valid Ethereum path
    /// let eth = Bip44Path::from_str("m/44'/60'/0'/0/0").unwrap();
    /// assert_eq!(eth.coin_type(), CoinType::Ethereum);
    ///
    /// // Invalid: missing hardening on account
    /// assert!(Bip44Path::from_str("m/44'/0'/0/0/0").is_err());
    ///
    /// // Invalid: wrong number of levels
    /// assert!(Bip44Path::from_str("m/44'/0'/0'").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self> {
        // Check if path starts with "m/"
        if !s.starts_with("m/") {
            return Err(Error::ParseError {
                reason: format!("Path must start with 'm/': {}", s),
            });
        }

        // Split the path into components
        let parts: Vec<&str> = s[2..].split('/').collect();

        // BIP-44 paths must have exactly 5 levels
        if parts.len() != 5 {
            return Err(Error::ParseError {
                reason: format!(
                    "BIP-44 path must have 5 levels, found {}: {}",
                    parts.len(),
                    s
                ),
            });
        }

        // Parse purpose (must be hardened)
        let purpose_str = parts[0];
        if !purpose_str.ends_with('\'') {
            return Err(Error::ParseError {
                reason: format!("Purpose must be hardened (end with '): {}", s),
            });
        }
        let purpose_value: u32 =
            purpose_str[..purpose_str.len() - 1]
                .parse()
                .map_err(|_| Error::ParseError {
                    reason: format!("Invalid purpose value '{}' in path: {}", purpose_str, s),
                })?;
        let purpose = Purpose::try_from(purpose_value)?;

        // Parse coin_type (must be hardened)
        let coin_type_str = parts[1];
        if !coin_type_str.ends_with('\'') {
            return Err(Error::ParseError {
                reason: format!("Coin type must be hardened (end with '): {}", s),
            });
        }
        let coin_type_value: u32 =
            coin_type_str[..coin_type_str.len() - 1]
                .parse()
                .map_err(|_| Error::ParseError {
                    reason: format!("Invalid coin type value '{}' in path: {}", coin_type_str, s),
                })?;
        let coin_type = CoinType::try_from(coin_type_value)?;

        // Parse account (must be hardened)
        let account_str = parts[2];
        if !account_str.ends_with('\'') {
            return Err(Error::ParseError {
                reason: format!("Account must be hardened (end with '): {}", s),
            });
        }
        let account: u32 =
            account_str[..account_str.len() - 1]
                .parse()
                .map_err(|_| Error::ParseError {
                    reason: format!("Invalid account value '{}' in path: {}", account_str, s),
                })?;

        // Parse chain (must NOT be hardened)
        let chain_str = parts[3];
        if chain_str.ends_with('\'') {
            return Err(Error::ParseError {
                reason: format!("Chain must not be hardened: {}", s),
            });
        }
        let chain_value: u32 = chain_str.parse().map_err(|_| Error::ParseError {
            reason: format!("Invalid chain value '{}' in path: {}", chain_str, s),
        })?;
        let chain = Chain::try_from(chain_value)?;

        // Parse address_index (must NOT be hardened)
        let address_str = parts[4];
        if address_str.ends_with('\'') {
            return Err(Error::ParseError {
                reason: format!("Address index must not be hardened: {}", s),
            });
        }
        let address_index: u32 = address_str.parse().map_err(|_| Error::ParseError {
            reason: format!(
                "Invalid address index value '{}' in path: {}",
                address_str, s
            ),
        })?;

        // Create the path using the constructor (which validates account range)
        Bip44Path::new(purpose, coin_type, account, chain, address_index)
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
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

        assert_eq!(path.purpose(), Purpose::BIP44);
        assert_eq!(path.coin_type(), CoinType::Bitcoin);
        assert_eq!(path.account(), 0);
        assert_eq!(path.chain(), Chain::External);
        assert_eq!(path.address_index(), 0);
    }

    #[test]
    fn test_new_with_different_purposes() {
        for purpose in [
            Purpose::BIP44,
            Purpose::BIP49,
            Purpose::BIP84,
            Purpose::BIP86,
        ] {
            let path = Bip44Path::new(purpose, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
            assert_eq!(path.purpose(), purpose);
        }
    }

    #[test]
    fn test_new_with_different_coins() {
        let btc = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(btc.coin_type(), CoinType::Bitcoin);

        let eth =
            Bip44Path::new(Purpose::BIP44, CoinType::Ethereum, 0, Chain::External, 0).unwrap();
        assert_eq!(eth.coin_type(), CoinType::Ethereum);

        let custom =
            Bip44Path::new(Purpose::BIP44, CoinType::Custom(999), 0, Chain::External, 0).unwrap();
        assert_eq!(custom.coin_type(), CoinType::Custom(999));
    }

    #[test]
    fn test_new_with_different_accounts() {
        let acc0 =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(acc0.account(), 0);

        let acc1 =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 1, Chain::External, 0).unwrap();
        assert_eq!(acc1.account(), 1);

        let acc_max = Bip44Path::new(
            Purpose::BIP44,
            CoinType::Bitcoin,
            MAX_HARDENED_INDEX,
            Chain::External,
            0,
        )
        .unwrap();
        assert_eq!(acc_max.account(), MAX_HARDENED_INDEX);
    }

    #[test]
    fn test_new_with_different_chains() {
        let external =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(external.chain(), Chain::External);

        let internal =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::Internal, 0).unwrap();
        assert_eq!(internal.chain(), Chain::Internal);
    }

    #[test]
    fn test_new_with_different_address_indices() {
        let addr0 =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(addr0.address_index(), 0);

        let addr100 =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 100).unwrap();
        assert_eq!(addr100.address_index(), 100);

        let addr_max = Bip44Path::new(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Chain::External,
            u32::MAX,
        )
        .unwrap();
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
        let path1 =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let path2 =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let path3 =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 1, Chain::External, 0).unwrap();

        assert_eq!(path1, path2);
        assert_ne!(path1, path3);
    }

    #[test]
    fn test_path_clone() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let cloned = path;
        assert_eq!(path, cloned);
    }

    #[test]
    fn test_path_debug() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let debug = format!("{:?}", path);
        assert!(debug.contains("Bip44Path"));
    }

    #[test]
    fn test_realistic_paths() {
        // Bitcoin first receiving address: m/44'/0'/0'/0/0
        let btc_first =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(btc_first.purpose(), Purpose::BIP44);
        assert_eq!(btc_first.coin_type(), CoinType::Bitcoin);

        // Ethereum second account, fifth change address: m/44'/60'/1'/1/4
        let eth_change =
            Bip44Path::new(Purpose::BIP44, CoinType::Ethereum, 1, Chain::Internal, 4).unwrap();
        assert_eq!(eth_change.account(), 1);
        assert_eq!(eth_change.chain(), Chain::Internal);
        assert_eq!(eth_change.address_index(), 4);

        // Native SegWit Bitcoin: m/84'/0'/0'/0/0
        let btc_segwit =
            Bip44Path::new(Purpose::BIP84, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
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

        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
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

        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Ethereum, 0, Chain::External, 0).unwrap();
        let derivation = path.to_derivation_path();

        // Should equal m/44'/60'/0'/0/0
        let expected = DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_to_derivation_path_with_different_account() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 5, Chain::External, 0).unwrap();
        let derivation = path.to_derivation_path();

        let expected = DerivationPath::from_str("m/44'/0'/5'/0/0").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_to_derivation_path_with_internal_chain() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::Internal, 0).unwrap();
        let derivation = path.to_derivation_path();

        let expected = DerivationPath::from_str("m/44'/0'/0'/1/0").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_to_derivation_path_with_address_index() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 42).unwrap();
        let derivation = path.to_derivation_path();

        let expected = DerivationPath::from_str("m/44'/0'/0'/0/42").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_to_derivation_path_bip84() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path =
            Bip44Path::new(Purpose::BIP84, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let derivation = path.to_derivation_path();

        // Should equal m/84'/0'/0'/0/0
        let expected = DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_to_derivation_path_custom_coin() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Custom(999), 0, Chain::External, 0).unwrap();
        let derivation = path.to_derivation_path();

        let expected = DerivationPath::from_str("m/44'/999'/0'/0/0").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_from_trait_conversion() {
        use khodpay_bip32::DerivationPath;

        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

        // Test From<Bip44Path>
        let derivation: DerivationPath = path.into();
        assert_eq!(derivation.depth(), 5);
    }

    #[test]
    fn test_from_ref_trait_conversion() {
        use khodpay_bip32::DerivationPath;

        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

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
        let path =
            Bip44Path::new(Purpose::BIP84, CoinType::Ethereum, 5, Chain::Internal, 100).unwrap();

        let derivation = path.to_derivation_path();
        let expected = DerivationPath::from_str("m/84'/60'/5'/1/100").unwrap();
        assert_eq!(derivation, expected);
    }

    #[test]
    fn test_conversion_preserves_hardening() {
        use khodpay_bip32::ChildNumber;

        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
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
        for purpose in [
            Purpose::BIP44,
            Purpose::BIP49,
            Purpose::BIP84,
            Purpose::BIP86,
        ] {
            let path = Bip44Path::new(purpose, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
            let derivation = path.to_derivation_path();
            assert_eq!(derivation.depth(), 5);
        }
    }

    #[test]
    fn test_conversion_display_format() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 5).unwrap();
        let derivation = path.to_derivation_path();

        // Check string representation
        assert_eq!(derivation.to_string(), "m/44'/0'/0'/0/5");
    }

    // Display tests
    #[test]
    fn test_display_bitcoin() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_display_ethereum() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Ethereum, 0, Chain::External, 0).unwrap();
        assert_eq!(path.to_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn test_display_with_account() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 5, Chain::External, 0).unwrap();
        assert_eq!(path.to_string(), "m/44'/0'/5'/0/0");
    }

    #[test]
    fn test_display_internal_chain() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::Internal, 0).unwrap();
        assert_eq!(path.to_string(), "m/44'/0'/0'/1/0");
    }

    #[test]
    fn test_display_with_address_index() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 42).unwrap();
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/42");
    }

    #[test]
    fn test_display_bip84() {
        let path =
            Bip44Path::new(Purpose::BIP84, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(path.to_string(), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn test_display_complex_path() {
        let path =
            Bip44Path::new(Purpose::BIP49, CoinType::Litecoin, 10, Chain::Internal, 999).unwrap();
        assert_eq!(path.to_string(), "m/49'/2'/10'/1/999");
    }

    #[test]
    fn test_display_custom_coin() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Custom(999), 0, Chain::External, 0).unwrap();
        assert_eq!(path.to_string(), "m/44'/999'/0'/0/0");
    }

    // FromStr tests
    #[test]
    fn test_from_str_bitcoin() {
        let path = Bip44Path::from_str("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.purpose(), Purpose::BIP44);
        assert_eq!(path.coin_type(), CoinType::Bitcoin);
        assert_eq!(path.account(), 0);
        assert_eq!(path.chain(), Chain::External);
        assert_eq!(path.address_index(), 0);
    }

    #[test]
    fn test_from_str_ethereum() {
        let path = Bip44Path::from_str("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(path.coin_type(), CoinType::Ethereum);
    }

    #[test]
    fn test_from_str_with_account() {
        let path = Bip44Path::from_str("m/44'/0'/5'/0/0").unwrap();
        assert_eq!(path.account(), 5);
    }

    #[test]
    fn test_from_str_internal_chain() {
        let path = Bip44Path::from_str("m/44'/0'/0'/1/0").unwrap();
        assert_eq!(path.chain(), Chain::Internal);
    }

    #[test]
    fn test_from_str_with_address_index() {
        let path = Bip44Path::from_str("m/44'/0'/0'/0/42").unwrap();
        assert_eq!(path.address_index(), 42);
    }

    #[test]
    fn test_from_str_bip84() {
        let path = Bip44Path::from_str("m/84'/0'/0'/0/0").unwrap();
        assert_eq!(path.purpose(), Purpose::BIP84);
    }

    #[test]
    fn test_from_str_complex_path() {
        let path = Bip44Path::from_str("m/49'/2'/10'/1/999").unwrap();
        assert_eq!(path.purpose(), Purpose::BIP49);
        assert_eq!(path.coin_type(), CoinType::Litecoin);
        assert_eq!(path.account(), 10);
        assert_eq!(path.chain(), Chain::Internal);
        assert_eq!(path.address_index(), 999);
    }

    #[test]
    fn test_from_str_custom_coin() {
        let path = Bip44Path::from_str("m/44'/999'/0'/0/0").unwrap();
        assert_eq!(path.coin_type(), CoinType::Custom(999));
    }

    #[test]
    fn test_from_str_invalid_no_m_prefix() {
        let result = Bip44Path::from_str("44'/0'/0'/0/0");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::ParseError { .. }));
    }

    #[test]
    fn test_from_str_invalid_wrong_depth() {
        let result = Bip44Path::from_str("m/44'/0'/0'");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_invalid_purpose_not_hardened() {
        let result = Bip44Path::from_str("m/44/0'/0'/0/0");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_invalid_coin_not_hardened() {
        let result = Bip44Path::from_str("m/44'/0/0'/0/0");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_invalid_account_not_hardened() {
        let result = Bip44Path::from_str("m/44'/0'/0/0/0");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_invalid_chain_hardened() {
        let result = Bip44Path::from_str("m/44'/0'/0'/0'/0");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_invalid_address_hardened() {
        let result = Bip44Path::from_str("m/44'/0'/0'/0/0'");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_invalid_purpose_value() {
        let result = Bip44Path::from_str("m/99'/0'/0'/0/0");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_invalid_chain_value() {
        let result = Bip44Path::from_str("m/44'/0'/0'/5/0");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_invalid_account_too_large() {
        let result = Bip44Path::from_str("m/44'/0'/2147483648'/0/0");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_invalid_not_a_number() {
        let result = Bip44Path::from_str("m/44'/abc'/0'/0/0");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_empty_string() {
        let result = Bip44Path::from_str("");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_str_only_m() {
        let result = Bip44Path::from_str("m/");
        assert!(result.is_err());
    }

    #[test]
    fn test_round_trip_display_from_str() {
        let original =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let string = original.to_string();
        let parsed = Bip44Path::from_str(&string).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_round_trip_complex_path() {
        let original =
            Bip44Path::new(Purpose::BIP84, CoinType::Ethereum, 5, Chain::Internal, 100).unwrap();
        let string = original.to_string();
        let parsed = Bip44Path::from_str(&string).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(string, "m/84'/60'/5'/1/100");
    }

    #[test]
    fn test_round_trip_all_purposes() {
        for purpose in [
            Purpose::BIP44,
            Purpose::BIP49,
            Purpose::BIP84,
            Purpose::BIP86,
        ] {
            let original =
                Bip44Path::new(purpose, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
            let string = original.to_string();
            let parsed = Bip44Path::from_str(&string).unwrap();
            assert_eq!(original, parsed);
        }
    }

    #[test]
    fn test_display_formatting() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(format!("{}", path), "m/44'/0'/0'/0/0");
        assert!(format!("{:?}", path).contains("Bip44Path"));
    }

    // Validation tests
    #[test]
    fn test_is_valid() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert!(path.is_valid());

        let path2 = Bip44Path::new(
            Purpose::BIP84,
            CoinType::Ethereum,
            100,
            Chain::Internal,
            u32::MAX,
        )
        .unwrap();
        assert!(path2.is_valid());
    }

    #[test]
    fn test_depth() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        assert_eq!(path.depth(), 5);
    }

    #[test]
    fn test_try_from_derivation_path_valid() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let bip44 = Bip44Path::try_from(derivation).unwrap();

        assert_eq!(bip44.purpose(), Purpose::BIP44);
        assert_eq!(bip44.coin_type(), CoinType::Bitcoin);
        assert_eq!(bip44.account(), 0);
        assert_eq!(bip44.chain(), Chain::External);
        assert_eq!(bip44.address_index(), 0);
    }

    #[test]
    fn test_try_from_derivation_path_ethereum() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap();
        let bip44 = Bip44Path::try_from(derivation).unwrap();

        assert_eq!(bip44.coin_type(), CoinType::Ethereum);
    }

    #[test]
    fn test_try_from_derivation_path_bip84() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap();
        let bip44 = Bip44Path::try_from(derivation).unwrap();

        assert_eq!(bip44.purpose(), Purpose::BIP84);
    }

    #[test]
    fn test_try_from_derivation_path_complex() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/49'/2'/10'/1/999").unwrap();
        let bip44 = Bip44Path::try_from(derivation).unwrap();

        assert_eq!(bip44.purpose(), Purpose::BIP49);
        assert_eq!(bip44.coin_type(), CoinType::Litecoin);
        assert_eq!(bip44.account(), 10);
        assert_eq!(bip44.chain(), Chain::Internal);
        assert_eq!(bip44.address_index(), 999);
    }

    #[test]
    fn test_try_from_derivation_path_ref() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let bip44 = Bip44Path::try_from(&derivation).unwrap();

        assert_eq!(bip44.purpose(), Purpose::BIP44);
        // Original should still be usable
        assert_eq!(derivation.depth(), 5);
    }

    #[test]
    fn test_try_from_derivation_path_invalid_depth_too_short() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        let result = Bip44Path::try_from(derivation);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidDepth { depth: 3 }
        ));
    }

    #[test]
    fn test_try_from_derivation_path_invalid_depth_too_long() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44'/0'/0'/0/0/1").unwrap();
        let result = Bip44Path::try_from(derivation);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidDepth { depth: 6 }
        ));
    }

    #[test]
    fn test_try_from_derivation_path_invalid_purpose_not_hardened() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44/0'/0'/0/0").unwrap();
        let result = Bip44Path::try_from(derivation);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidHardenedLevel { .. }
        ));
    }

    #[test]
    fn test_try_from_derivation_path_invalid_coin_not_hardened() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44'/0/0'/0/0").unwrap();
        let result = Bip44Path::try_from(derivation);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidHardenedLevel { .. }
        ));
    }

    #[test]
    fn test_try_from_derivation_path_invalid_account_not_hardened() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44'/0'/0/0/0").unwrap();
        let result = Bip44Path::try_from(derivation);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidHardenedLevel { .. }
        ));
    }

    #[test]
    fn test_try_from_derivation_path_invalid_chain_hardened() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44'/0'/0'/0'/0").unwrap();
        let result = Bip44Path::try_from(derivation);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidHardenedLevel { .. }
        ));
    }

    #[test]
    fn test_try_from_derivation_path_invalid_address_hardened() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44'/0'/0'/0/0'").unwrap();
        let result = Bip44Path::try_from(derivation);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidHardenedLevel { .. }
        ));
    }

    #[test]
    fn test_try_from_derivation_path_invalid_purpose_value() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/99'/0'/0'/0/0").unwrap();
        let result = Bip44Path::try_from(derivation);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPurpose { value: 99 }
        ));
    }

    #[test]
    fn test_try_from_derivation_path_invalid_chain_value() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44'/0'/0'/5/0").unwrap();
        let result = Bip44Path::try_from(derivation);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidChain { value: 5 }
        ));
    }

    #[test]
    fn test_try_from_derivation_path_invalid_account_too_large() {
        use khodpay_bip32::{ChildNumber, DerivationPath};

        let derivation = DerivationPath::new(vec![
            ChildNumber::Hardened(44),
            ChildNumber::Hardened(0),
            ChildNumber::Hardened(MAX_HARDENED_INDEX + 1),
            ChildNumber::Normal(0),
            ChildNumber::Normal(0),
        ]);

        let result = Bip44Path::try_from(derivation);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidAccount { .. }));
    }

    #[test]
    fn test_try_from_derivation_path_custom_coin() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/44'/999'/0'/0/0").unwrap();
        let bip44 = Bip44Path::try_from(derivation).unwrap();

        assert_eq!(bip44.coin_type(), CoinType::Custom(999));
    }

    #[test]
    fn test_round_trip_bip44_to_derivation_to_bip44() {
        let original =
            Bip44Path::new(Purpose::BIP84, CoinType::Ethereum, 5, Chain::Internal, 100).unwrap();

        let derivation: DerivationPath = original.into();
        let converted = Bip44Path::try_from(derivation).unwrap();

        assert_eq!(original, converted);
    }

    #[test]
    fn test_validation_all_purposes() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        for (purpose_val, expected) in [
            (44, Purpose::BIP44),
            (49, Purpose::BIP49),
            (84, Purpose::BIP84),
            (86, Purpose::BIP86),
        ] {
            let path_str = format!("m/{}'/0'/0'/0/0", purpose_val);
            let derivation = DerivationPath::from_str(&path_str).unwrap();
            let bip44 = Bip44Path::try_from(derivation).unwrap();
            assert_eq!(bip44.purpose(), expected);
        }
    }

    #[test]
    fn test_validation_preserves_all_fields() {
        use khodpay_bip32::DerivationPath;
        use std::str::FromStr;

        let derivation = DerivationPath::from_str("m/49'/2'/10'/1/999").unwrap();
        let bip44 = Bip44Path::try_from(derivation).unwrap();

        assert_eq!(bip44.purpose().value(), 49);
        assert_eq!(bip44.coin_type().index(), 2);
        assert_eq!(bip44.account(), 10);
        assert_eq!(bip44.chain().value(), 1);
        assert_eq!(bip44.address_index(), 999);
    }

    // Path manipulation tests
    #[test]
    fn test_next_address() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let next = path.next_address();

        assert_eq!(next.address_index(), 1);
        assert_eq!(next.chain(), Chain::External);
        assert_eq!(next.account(), 0);
        assert_eq!(next.purpose(), Purpose::BIP44);
        assert_eq!(next.coin_type(), CoinType::Bitcoin);
    }

    #[test]
    fn test_next_address_sequence() {
        let mut path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

        for i in 1..=10 {
            path = path.next_address();
            assert_eq!(path.address_index(), i);
        }
    }

    #[test]
    fn test_next_address_wrapping() {
        let path = Bip44Path::new(
            Purpose::BIP44,
            CoinType::Bitcoin,
            0,
            Chain::External,
            u32::MAX,
        )
        .unwrap();
        let next = path.next_address();

        assert_eq!(next.address_index(), 0); // Wraps around
    }

    #[test]
    fn test_with_address_index() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let new_path = path.with_address_index(100);

        assert_eq!(new_path.address_index(), 100);
        assert_eq!(new_path.chain(), path.chain());
        assert_eq!(new_path.account(), path.account());
    }

    #[test]
    fn test_with_chain() {
        let external =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 5).unwrap();
        let internal = external.with_chain(Chain::Internal);

        assert_eq!(internal.chain(), Chain::Internal);
        assert_eq!(internal.address_index(), 5);
        assert_eq!(internal.account(), 0);
    }

    #[test]
    fn test_to_external() {
        let change =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::Internal, 5).unwrap();
        let receive = change.to_external();

        assert_eq!(receive.chain(), Chain::External);
        assert_eq!(receive.address_index(), 5);
    }

    #[test]
    fn test_to_internal() {
        let receive =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 5).unwrap();
        let change = receive.to_internal();

        assert_eq!(change.chain(), Chain::Internal);
        assert_eq!(change.address_index(), 5);
    }

    #[test]
    fn test_chain_switching() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 10).unwrap();
        let internal = path.to_internal();
        let external_again = internal.to_external();

        assert_eq!(external_again.chain(), Chain::External);
        assert_eq!(external_again.address_index(), 10);
    }

    #[test]
    fn test_with_account() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let new_path = path.with_account(5).unwrap();

        assert_eq!(new_path.account(), 5);
        assert_eq!(new_path.purpose(), path.purpose());
        assert_eq!(new_path.coin_type(), path.coin_type());
    }

    #[test]
    fn test_with_account_invalid() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let result = path.with_account(MAX_HARDENED_INDEX + 1);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidAccount { .. }));
    }

    #[test]
    fn test_next_account() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let next = path.next_account().unwrap();

        assert_eq!(next.account(), 1);
        assert_eq!(next.purpose(), path.purpose());
        assert_eq!(next.coin_type(), path.coin_type());
    }

    #[test]
    fn test_next_account_sequence() {
        let mut path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

        for i in 1..=5 {
            path = path.next_account().unwrap();
            assert_eq!(path.account(), i);
        }
    }

    #[test]
    fn test_next_account_overflow() {
        let path = Bip44Path::new(
            Purpose::BIP44,
            CoinType::Bitcoin,
            MAX_HARDENED_INDEX,
            Chain::External,
            0,
        )
        .unwrap();
        let result = path.next_account();

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidAccount { .. }));
    }

    #[test]
    fn test_with_purpose() {
        let bip44 =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let bip84 = bip44.with_purpose(Purpose::BIP84);

        assert_eq!(bip84.purpose(), Purpose::BIP84);
        assert_eq!(bip84.coin_type(), bip44.coin_type());
        assert_eq!(bip84.account(), bip44.account());
    }

    #[test]
    fn test_purpose_switching() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

        for purpose in [
            Purpose::BIP44,
            Purpose::BIP49,
            Purpose::BIP84,
            Purpose::BIP86,
        ] {
            let new_path = path.with_purpose(purpose);
            assert_eq!(new_path.purpose(), purpose);
        }
    }

    #[test]
    fn test_with_coin_type() {
        let btc = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let eth = btc.with_coin_type(CoinType::Ethereum);

        assert_eq!(eth.coin_type(), CoinType::Ethereum);
        assert_eq!(eth.purpose(), btc.purpose());
        assert_eq!(eth.account(), btc.account());
    }

    #[test]
    fn test_coin_type_switching() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

        let eth = path.with_coin_type(CoinType::Ethereum);
        let ltc = eth.with_coin_type(CoinType::Litecoin);
        let custom = ltc.with_coin_type(CoinType::Custom(999));

        assert_eq!(custom.coin_type(), CoinType::Custom(999));
    }

    #[test]
    fn test_complex_path_manipulation() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

        let result = path
            .next_address()
            .next_address()
            .to_internal()
            .with_address_index(5)
            .next_account()
            .unwrap()
            .with_purpose(Purpose::BIP84);

        assert_eq!(result.purpose(), Purpose::BIP84);
        assert_eq!(result.account(), 1);
        assert_eq!(result.chain(), Chain::Internal);
        assert_eq!(result.address_index(), 5);
    }

    #[test]
    fn test_path_immutability() {
        let original =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let _modified = original.next_address();

        // Original should be unchanged
        assert_eq!(original.address_index(), 0);
    }

    #[test]
    fn test_generate_address_range() {
        let base =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let mut paths = vec![base];

        for _ in 0..9 {
            paths.push(paths.last().unwrap().next_address());
        }

        assert_eq!(paths.len(), 10);
        for (i, path) in paths.iter().enumerate() {
            assert_eq!(path.address_index(), i as u32);
        }
    }

    #[test]
    fn test_account_and_chain_combination() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

        // Switch to account 1, internal chain
        let modified = path.with_account(1).unwrap().to_internal();

        assert_eq!(modified.account(), 1);
        assert_eq!(modified.chain(), Chain::Internal);
        assert_eq!(modified.address_index(), 0);
    }

    #[test]
    fn test_all_fields_independence() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

        let modified = path
            .with_purpose(Purpose::BIP84)
            .with_coin_type(CoinType::Ethereum)
            .with_account(5)
            .unwrap()
            .with_chain(Chain::Internal)
            .with_address_index(100);

        assert_eq!(modified.purpose(), Purpose::BIP84);
        assert_eq!(modified.coin_type(), CoinType::Ethereum);
        assert_eq!(modified.account(), 5);
        assert_eq!(modified.chain(), Chain::Internal);
        assert_eq!(modified.address_index(), 100);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_deserialize() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 5).unwrap();

        let json = serde_json::to_string(&path).unwrap();
        let deserialized: Bip44Path = serde_json::from_str(&json).unwrap();

        assert_eq!(path, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_format() {
        let path =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

        let json = serde_json::to_string(&path).unwrap();
        assert!(json.contains("\"purpose\""));
        assert!(json.contains("\"coin_type\""));
        assert!(json.contains("\"account\""));
        assert!(json.contains("\"chain\""));
        assert!(json.contains("\"address_index\""));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialize_from_json() {
        let json = r#"{"purpose":"BIP44","coin_type":"Bitcoin","account":0,"chain":"External","address_index":5}"#;
        let path: Bip44Path = serde_json::from_str(json).unwrap();

        assert_eq!(path.purpose(), Purpose::BIP44);
        assert_eq!(path.coin_type(), CoinType::Bitcoin);
        assert_eq!(path.account(), 0);
        assert_eq!(path.chain(), Chain::External);
        assert_eq!(path.address_index(), 5);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_different_purposes() {
        let bip44 =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let bip49 =
            Bip44Path::new(Purpose::BIP49, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let bip84 =
            Bip44Path::new(Purpose::BIP84, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();

        let json44 = serde_json::to_string(&bip44).unwrap();
        let json49 = serde_json::to_string(&bip49).unwrap();
        let json84 = serde_json::to_string(&bip84).unwrap();

        assert!(json44.contains("BIP44"));
        assert!(json49.contains("BIP49"));
        assert!(json84.contains("BIP84"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_different_coins() {
        let btc = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let eth =
            Bip44Path::new(Purpose::BIP44, CoinType::Ethereum, 0, Chain::External, 0).unwrap();

        let json_btc = serde_json::to_string(&btc).unwrap();
        let json_eth = serde_json::to_string(&eth).unwrap();

        assert!(json_btc.contains("Bitcoin"));
        assert!(json_eth.contains("Ethereum"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serialize_both_chains() {
        let external =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
        let internal =
            Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::Internal, 0).unwrap();

        let json_ext = serde_json::to_string(&external).unwrap();
        let json_int = serde_json::to_string(&internal).unwrap();

        assert!(json_ext.contains("External"));
        assert!(json_int.contains("Internal"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_serde_round_trip_complex() {
        let path =
            Bip44Path::new(Purpose::BIP84, CoinType::Ethereum, 5, Chain::Internal, 1000).unwrap();

        let json = serde_json::to_string(&path).unwrap();
        let deserialized: Bip44Path = serde_json::from_str(&json).unwrap();

        assert_eq!(path, deserialized);
        assert_eq!(deserialized.purpose(), Purpose::BIP84);
        assert_eq!(deserialized.coin_type(), CoinType::Ethereum);
        assert_eq!(deserialized.account(), 5);
        assert_eq!(deserialized.chain(), Chain::Internal);
        assert_eq!(deserialized.address_index(), 1000);
    }
}
