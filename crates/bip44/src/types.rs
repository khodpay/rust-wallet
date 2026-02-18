//! Core types for BIP-44 multi-account hierarchy.
//!
//! This module defines the fundamental types used in BIP-44 path construction:
//! - [`Purpose`]: Derivation standard (BIP-44, BIP-49, BIP-84, BIP-86)
//! - [`Chain`]: Address chain type (External/Internal)
//! - [`CoinType`]: Cryptocurrency type (Bitcoin, Ethereum, etc.)
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip44::{Purpose, Chain};
//!
//! // Create a purpose and chain
//! let purpose = Purpose::BIP44;
//! let chain = Chain::External;
//!
//! // Convert to u32 for derivation
//! let chain_value: u32 = chain.into();
//! assert_eq!(chain_value, 0);
//! ```

use crate::{Error, Result};
use std::fmt;

/// Derivation purpose constants defining different address format standards.
///
/// The purpose field in BIP-44 paths indicates which derivation standard to use,
/// which determines the resulting address format and structure.
///
/// # Purpose Standards
///
/// - **BIP-44 (44')**: Legacy P2PKH addresses (e.g., "1...")
/// - **BIP-49 (49')**: SegWit wrapped in P2SH (e.g., "3...")
/// - **BIP-84 (84')**: Native SegWit P2WPKH (e.g., "bc1q...")
/// - **BIP-86 (86')**: Taproot P2TR (e.g., "bc1p...")
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::Purpose;
///
/// // Create different purpose types
/// let legacy = Purpose::BIP44;
/// let segwit = Purpose::BIP84;
///
/// // Convert to u32 for derivation
/// let value: u32 = legacy.into();
/// assert_eq!(value, 44);
///
/// // Parse from u32
/// let parsed = Purpose::try_from(84).unwrap();
/// assert_eq!(parsed, Purpose::BIP84);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Purpose {
    /// BIP-44: Legacy P2PKH addresses.
    ///
    /// Traditional Bitcoin addresses starting with "1". This was the original
    /// address format and is still widely supported.
    ///
    /// Path: `m/44'/coin'/account'/chain/index`
    BIP44,

    /// BIP-49: SegWit wrapped in P2SH (P2WPKH-nested-in-P2SH).
    ///
    /// SegWit addresses wrapped in Pay-to-Script-Hash for backward compatibility.
    /// These addresses start with "3" and were used during SegWit adoption.
    ///
    /// Path: `m/49'/coin'/account'/chain/index`
    BIP49,

    /// BIP-84: Native SegWit P2WPKH addresses.
    ///
    /// Native Segregated Witness addresses using Bech32 encoding.
    /// These addresses start with "bc1q" for Bitcoin mainnet.
    ///
    /// Path: `m/84'/coin'/account'/chain/index`
    BIP84,

    /// BIP-86: Taproot P2TR addresses.
    ///
    /// Taproot addresses using Bech32m encoding, introduced in Bitcoin's
    /// Taproot upgrade. These addresses start with "bc1p" for Bitcoin mainnet.
    ///
    /// Path: `m/86'/coin'/account'/chain/index`
    BIP86,
}

impl Purpose {
    /// Returns the u32 value for this purpose (44, 49, 84, or 86).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Purpose;
    ///
    /// assert_eq!(Purpose::BIP44.value(), 44);
    /// assert_eq!(Purpose::BIP84.value(), 84);
    /// ```
    pub const fn value(&self) -> u32 {
        match self {
            Purpose::BIP44 => 44,
            Purpose::BIP49 => 49,
            Purpose::BIP84 => 84,
            Purpose::BIP86 => 86,
        }
    }

    /// Returns the name of the purpose standard.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Purpose;
    ///
    /// assert_eq!(Purpose::BIP44.name(), "BIP-44");
    /// assert_eq!(Purpose::BIP84.name(), "BIP-84");
    /// ```
    pub const fn name(&self) -> &'static str {
        match self {
            Purpose::BIP44 => "BIP-44",
            Purpose::BIP49 => "BIP-49",
            Purpose::BIP84 => "BIP-84",
            Purpose::BIP86 => "BIP-86",
        }
    }

    /// Returns a description of the address type for this purpose.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Purpose;
    ///
    /// assert_eq!(Purpose::BIP44.description(), "Legacy P2PKH");
    /// assert_eq!(Purpose::BIP84.description(), "Native SegWit");
    /// ```
    pub const fn description(&self) -> &'static str {
        match self {
            Purpose::BIP44 => "Legacy P2PKH",
            Purpose::BIP49 => "SegWit (P2SH-wrapped)",
            Purpose::BIP84 => "Native SegWit",
            Purpose::BIP86 => "Taproot",
        }
    }
}

impl TryFrom<u32> for Purpose {
    type Error = Error;

    /// Attempts to convert a u32 value to a Purpose.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPurpose`] if the value is not 44, 49, 84, or 86.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Purpose;
    ///
    /// // Valid conversions
    /// assert_eq!(Purpose::try_from(44).unwrap(), Purpose::BIP44);
    /// assert_eq!(Purpose::try_from(84).unwrap(), Purpose::BIP84);
    ///
    /// // Invalid value
    /// assert!(Purpose::try_from(99).is_err());
    /// ```
    fn try_from(value: u32) -> Result<Self> {
        match value {
            44 => Ok(Purpose::BIP44),
            49 => Ok(Purpose::BIP49),
            84 => Ok(Purpose::BIP84),
            86 => Ok(Purpose::BIP86),
            _ => Err(Error::InvalidPurpose { value }),
        }
    }
}

impl From<Purpose> for u32 {
    /// Converts a Purpose to its u32 value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Purpose;
    ///
    /// let value: u32 = Purpose::BIP44.into();
    /// assert_eq!(value, 44);
    /// ```
    fn from(purpose: Purpose) -> Self {
        purpose.value()
    }
}

impl fmt::Display for Purpose {
    /// Formats the purpose for display.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Purpose;
    ///
    /// assert_eq!(Purpose::BIP44.to_string(), "BIP-44");
    /// assert_eq!(Purpose::BIP84.to_string(), "BIP-84");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_purpose_values() {
        assert_eq!(Purpose::BIP44.value(), 44);
        assert_eq!(Purpose::BIP49.value(), 49);
        assert_eq!(Purpose::BIP84.value(), 84);
        assert_eq!(Purpose::BIP86.value(), 86);
    }

    #[test]
    fn test_purpose_names() {
        assert_eq!(Purpose::BIP44.name(), "BIP-44");
        assert_eq!(Purpose::BIP49.name(), "BIP-49");
        assert_eq!(Purpose::BIP84.name(), "BIP-84");
        assert_eq!(Purpose::BIP86.name(), "BIP-86");
    }

    #[test]
    fn test_purpose_descriptions() {
        assert_eq!(Purpose::BIP44.description(), "Legacy P2PKH");
        assert_eq!(Purpose::BIP49.description(), "SegWit (P2SH-wrapped)");
        assert_eq!(Purpose::BIP84.description(), "Native SegWit");
        assert_eq!(Purpose::BIP86.description(), "Taproot");
    }

    #[test]
    fn test_purpose_try_from_valid() {
        assert_eq!(Purpose::try_from(44).unwrap(), Purpose::BIP44);
        assert_eq!(Purpose::try_from(49).unwrap(), Purpose::BIP49);
        assert_eq!(Purpose::try_from(84).unwrap(), Purpose::BIP84);
        assert_eq!(Purpose::try_from(86).unwrap(), Purpose::BIP86);
    }

    #[test]
    fn test_purpose_try_from_invalid() {
        assert!(Purpose::try_from(0).is_err());
        assert!(Purpose::try_from(43).is_err());
        assert!(Purpose::try_from(45).is_err());
        assert!(Purpose::try_from(99).is_err());
        assert!(Purpose::try_from(100).is_err());
    }

    #[test]
    fn test_purpose_try_from_error_message() {
        let error = Purpose::try_from(99).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid purpose value: 99. Valid values are 44, 49, 84, or 86"
        );
    }

    #[test]
    fn test_purpose_into_u32() {
        let value: u32 = Purpose::BIP44.into();
        assert_eq!(value, 44);

        let value: u32 = Purpose::BIP84.into();
        assert_eq!(value, 84);
    }

    #[test]
    fn test_purpose_round_trip() {
        for purpose in [
            Purpose::BIP44,
            Purpose::BIP49,
            Purpose::BIP84,
            Purpose::BIP86,
        ] {
            let value: u32 = purpose.into();
            let parsed = Purpose::try_from(value).unwrap();
            assert_eq!(parsed, purpose);
        }
    }

    #[test]
    fn test_purpose_display() {
        assert_eq!(Purpose::BIP44.to_string(), "BIP-44");
        assert_eq!(Purpose::BIP49.to_string(), "BIP-49");
        assert_eq!(Purpose::BIP84.to_string(), "BIP-84");
        assert_eq!(Purpose::BIP86.to_string(), "BIP-86");
    }

    #[test]
    fn test_purpose_equality() {
        assert_eq!(Purpose::BIP44, Purpose::BIP44);
        assert_ne!(Purpose::BIP44, Purpose::BIP84);
    }

    #[test]
    fn test_purpose_clone() {
        let purpose = Purpose::BIP44;
        let cloned = purpose;
        assert_eq!(purpose, cloned);
    }

    #[test]
    fn test_purpose_debug() {
        let purpose = Purpose::BIP44;
        assert_eq!(format!("{:?}", purpose), "BIP44");
    }
}

/// Address chain type for BIP-44 derivation.
///
/// BIP-44 defines two distinct chains for address management:
/// - **External (0)**: Receiving addresses visible to others
/// - **Internal (1)**: Change addresses for internal wallet use
///
/// This separation allows wallets to maintain privacy by using different
/// addresses for receiving payments and returning change.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::Chain;
///
/// // Create chain types
/// let receive = Chain::External;
/// let change = Chain::Internal;
///
/// // Convert to u32 for derivation
/// let value: u32 = receive.into();
/// assert_eq!(value, 0);
///
/// // Parse from u32
/// let parsed = Chain::try_from(1).unwrap();
/// assert_eq!(parsed, Chain::Internal);
///
/// // Use helper methods
/// assert!(receive.is_external());
/// assert!(!change.is_external());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Chain {
    /// External chain (0) for receiving addresses.
    ///
    /// These addresses are meant to be shared with others for receiving payments.
    /// In BIP-44 terminology, this is the "receiving" chain.
    ///
    /// Path example: `m/44'/0'/0'/0/n` where n is the address index
    External,

    /// Internal chain (1) for change addresses.
    ///
    /// These addresses are used internally by the wallet for receiving change
    /// from transactions. They should not be shared externally.
    ///
    /// Path example: `m/44'/0'/0'/1/n` where n is the address index
    Internal,
}

impl Chain {
    /// Returns the u32 value for this chain (0 or 1).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Chain;
    ///
    /// assert_eq!(Chain::External.value(), 0);
    /// assert_eq!(Chain::Internal.value(), 1);
    /// ```
    pub const fn value(&self) -> u32 {
        match self {
            Chain::External => 0,
            Chain::Internal => 1,
        }
    }

    /// Returns `true` if this is the external (receiving) chain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Chain;
    ///
    /// assert!(Chain::External.is_external());
    /// assert!(!Chain::Internal.is_external());
    /// ```
    pub const fn is_external(&self) -> bool {
        matches!(self, Chain::External)
    }

    /// Returns `true` if this is the internal (change) chain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Chain;
    ///
    /// assert!(Chain::Internal.is_internal());
    /// assert!(!Chain::External.is_internal());
    /// ```
    pub const fn is_internal(&self) -> bool {
        matches!(self, Chain::Internal)
    }

    /// Returns the name of this chain type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Chain;
    ///
    /// assert_eq!(Chain::External.name(), "external");
    /// assert_eq!(Chain::Internal.name(), "internal");
    /// ```
    pub const fn name(&self) -> &'static str {
        match self {
            Chain::External => "external",
            Chain::Internal => "internal",
        }
    }
}

impl TryFrom<u32> for Chain {
    type Error = Error;

    /// Attempts to convert a u32 value to a Chain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidChain`] if the value is not 0 or 1.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Chain;
    ///
    /// // Valid conversions
    /// assert_eq!(Chain::try_from(0).unwrap(), Chain::External);
    /// assert_eq!(Chain::try_from(1).unwrap(), Chain::Internal);
    ///
    /// // Invalid value
    /// assert!(Chain::try_from(2).is_err());
    /// ```
    fn try_from(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Chain::External),
            1 => Ok(Chain::Internal),
            _ => Err(Error::InvalidChain { value }),
        }
    }
}

impl From<Chain> for u32 {
    /// Converts a Chain to its u32 value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Chain;
    ///
    /// let value: u32 = Chain::External.into();
    /// assert_eq!(value, 0);
    ///
    /// let value: u32 = Chain::Internal.into();
    /// assert_eq!(value, 1);
    /// ```
    fn from(chain: Chain) -> Self {
        chain.value()
    }
}

impl fmt::Display for Chain {
    /// Formats the chain for display.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Chain;
    ///
    /// assert_eq!(Chain::External.to_string(), "external");
    /// assert_eq!(Chain::Internal.to_string(), "internal");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;

    #[test]
    fn test_chain_values() {
        assert_eq!(Chain::External.value(), 0);
        assert_eq!(Chain::Internal.value(), 1);
    }

    #[test]
    fn test_chain_is_external() {
        assert!(Chain::External.is_external());
        assert!(!Chain::Internal.is_external());
    }

    #[test]
    fn test_chain_is_internal() {
        assert!(Chain::Internal.is_internal());
        assert!(!Chain::External.is_internal());
    }

    #[test]
    fn test_chain_names() {
        assert_eq!(Chain::External.name(), "external");
        assert_eq!(Chain::Internal.name(), "internal");
    }

    #[test]
    fn test_chain_try_from_valid() {
        assert_eq!(Chain::try_from(0).unwrap(), Chain::External);
        assert_eq!(Chain::try_from(1).unwrap(), Chain::Internal);
    }

    #[test]
    fn test_chain_try_from_invalid() {
        assert!(Chain::try_from(2).is_err());
        assert!(Chain::try_from(3).is_err());
        assert!(Chain::try_from(99).is_err());
        assert!(Chain::try_from(u32::MAX).is_err());
    }

    #[test]
    fn test_chain_try_from_error_message() {
        let error = Chain::try_from(2).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid chain value: 2 (must be 0 for external or 1 for internal)"
        );
    }

    #[test]
    fn test_chain_into_u32() {
        let value: u32 = Chain::External.into();
        assert_eq!(value, 0);

        let value: u32 = Chain::Internal.into();
        assert_eq!(value, 1);
    }

    #[test]
    fn test_chain_round_trip() {
        for chain in [Chain::External, Chain::Internal] {
            let value: u32 = chain.into();
            let parsed = Chain::try_from(value).unwrap();
            assert_eq!(parsed, chain);
        }
    }

    #[test]
    fn test_chain_display() {
        assert_eq!(Chain::External.to_string(), "external");
        assert_eq!(Chain::Internal.to_string(), "internal");
    }

    #[test]
    fn test_chain_equality() {
        assert_eq!(Chain::External, Chain::External);
        assert_eq!(Chain::Internal, Chain::Internal);
        assert_ne!(Chain::External, Chain::Internal);
    }

    #[test]
    fn test_chain_clone() {
        let chain = Chain::External;
        let cloned = chain;
        assert_eq!(chain, cloned);
    }

    #[test]
    fn test_chain_debug() {
        let chain = Chain::External;
        assert_eq!(format!("{:?}", chain), "External");

        let chain = Chain::Internal;
        assert_eq!(format!("{:?}", chain), "Internal");
    }
}

/// Cryptocurrency coin types according to SLIP-44 registry.
///
/// SLIP-44 defines a standard registry of coin type constants for use in
/// BIP-44 derivation paths. Each cryptocurrency has a unique index.
///
/// This enum provides variants for commonly used cryptocurrencies, plus a
/// `Custom` variant for coins not explicitly listed or future additions.
///
/// # SLIP-44 Standard
///
/// The coin type is the second level in BIP-44 paths and must use hardened
/// derivation. For example, Bitcoin uses coin type 0', represented as `2^31 + 0`.
///
/// Full registry: <https://github.com/satoshilabs/slips/blob/master/slip-0044.md>
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::CoinType;
///
/// // Use predefined coin types
/// let btc = CoinType::Bitcoin;
/// let eth = CoinType::Ethereum;
///
/// // Use custom coin type for unlisted coins
/// let custom = CoinType::Custom(501); // Solana
///
/// // Get SLIP-44 index
/// assert_eq!(btc.index(), 0);
/// assert_eq!(eth.index(), 60);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CoinType {
    /// Bitcoin (BTC) - Coin type 0.
    ///
    /// The original cryptocurrency and most widely used coin type.
    ///
    /// Network: Mainnet  
    /// Symbol: BTC  
    /// Path example: `m/44'/0'/0'/0/0`
    Bitcoin,

    /// Bitcoin Testnet - Coin type 1.
    ///
    /// Test network for Bitcoin, used for development and testing.
    ///
    /// Network: Testnet  
    /// Symbol: tBTC  
    /// Path example: `m/44'/1'/0'/0/0`
    BitcoinTestnet,

    /// Litecoin (LTC) - Coin type 2.
    ///
    /// One of the earliest Bitcoin forks, designed for faster transactions.
    ///
    /// Network: Mainnet  
    /// Symbol: LTC  
    /// Path example: `m/44'/2'/0'/0/0`
    Litecoin,

    /// Dogecoin (DOGE) - Coin type 3.
    ///
    /// Originally created as a joke, now a popular cryptocurrency.
    ///
    /// Network: Mainnet  
    /// Symbol: DOGE  
    /// Path example: `m/44'/3'/0'/0/0`
    Dogecoin,

    /// Dash (DASH) - Coin type 5.
    ///
    /// Privacy-focused cryptocurrency with instant transactions.
    ///
    /// Network: Mainnet  
    /// Symbol: DASH  
    /// Path example: `m/44'/5'/0'/0/0`
    Dash,

    /// Ethereum (ETH) - Coin type 60.
    ///
    /// Smart contract platform and second-largest cryptocurrency by market cap.
    ///
    /// Network: Mainnet  
    /// Symbol: ETH  
    /// Path example: `m/44'/60'/0'/0/0`
    Ethereum,

    /// Ethereum Classic (ETC) - Coin type 61.
    ///
    /// Original Ethereum chain after the DAO hard fork.
    ///
    /// Network: Mainnet  
    /// Symbol: ETC  
    /// Path example: `m/44'/61'/0'/0/0`
    EthereumClassic,

    /// Bitcoin Cash (BCH) - Coin type 145.
    ///
    /// Bitcoin fork with larger block sizes.
    ///
    /// Network: Mainnet  
    /// Symbol: BCH  
    /// Path example: `m/44'/145'/0'/0/0`
    BitcoinCash,

    /// Binance Coin (BNB) - Coin type 714.
    ///
    /// Native token of Binance Chain and Binance Smart Chain.
    ///
    /// Network: Mainnet  
    /// Symbol: BNB  
    /// Path example: `m/44'/714'/0'/0/0`
    BinanceCoin,

    /// Solana (SOL) - Coin type 501.
    ///
    /// High-performance blockchain with fast transactions.
    ///
    /// Network: Mainnet  
    /// Symbol: SOL  
    /// Path example: `m/44'/501'/0'/0/0`
    Solana,

    /// Cardano (ADA) - Coin type 1815.
    ///
    /// Proof-of-stake blockchain with academic research foundation.
    ///
    /// Network: Mainnet  
    /// Symbol: ADA  
    /// Path example: `m/44'/1815'/0'/0/0`
    Cardano,

    /// Polkadot (DOT) - Coin type 354.
    ///
    /// Multi-chain protocol for connecting different blockchains.
    ///
    /// Network: Mainnet  
    /// Symbol: DOT  
    /// Path example: `m/44'/354'/0'/0/0`
    Polkadot,

    /// Cosmos (ATOM) - Coin type 118.
    ///
    /// Internet of blockchains for interoperability.
    ///
    /// Network: Mainnet  
    /// Symbol: ATOM  
    /// Path example: `m/44'/118'/0'/0/0`
    Cosmos,

    /// Tron (TRX) - Coin type 195.
    ///
    /// Blockchain focused on content sharing and entertainment.
    ///
    /// Network: Mainnet  
    /// Symbol: TRX  
    /// Path example: `m/44'/195'/0'/0/0`
    Tron,

    /// Custom coin type for unlisted or future cryptocurrencies.
    ///
    /// Use this variant for coins not explicitly defined in this enum.
    /// The inner value is the SLIP-44 registered coin type index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::CoinType;
    ///
    /// // Use custom coin type for Monero (128)
    /// let monero = CoinType::Custom(128);
    /// assert_eq!(monero.index(), 128);
    ///
    /// // Use custom for any registered SLIP-44 coin
    /// let zcash = CoinType::Custom(133);
    /// ```
    Custom(u32),
}

impl CoinType {
    /// Returns the SLIP-44 coin type index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::CoinType;
    ///
    /// assert_eq!(CoinType::Bitcoin.index(), 0);
    /// assert_eq!(CoinType::Ethereum.index(), 60);
    /// assert_eq!(CoinType::Custom(999).index(), 999);
    /// ```
    pub const fn index(&self) -> u32 {
        match self {
            CoinType::Bitcoin => 0,
            CoinType::BitcoinTestnet => 1,
            CoinType::Litecoin => 2,
            CoinType::Dogecoin => 3,
            CoinType::Dash => 5,
            CoinType::Ethereum => 60,
            CoinType::EthereumClassic => 61,
            CoinType::BitcoinCash => 145,
            CoinType::BinanceCoin => 714,
            CoinType::Solana => 501,
            CoinType::Cardano => 1815,
            CoinType::Polkadot => 354,
            CoinType::Cosmos => 118,
            CoinType::Tron => 195,
            CoinType::Custom(index) => *index,
        }
    }

    /// Returns the symbol for this coin type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::CoinType;
    ///
    /// assert_eq!(CoinType::Bitcoin.symbol(), "BTC");
    /// assert_eq!(CoinType::Ethereum.symbol(), "ETH");
    /// assert_eq!(CoinType::Custom(999).symbol(), "CUSTOM");
    /// ```
    pub const fn symbol(&self) -> &'static str {
        match self {
            CoinType::Bitcoin => "BTC",
            CoinType::BitcoinTestnet => "tBTC",
            CoinType::Litecoin => "LTC",
            CoinType::Dogecoin => "DOGE",
            CoinType::Dash => "DASH",
            CoinType::Ethereum => "ETH",
            CoinType::EthereumClassic => "ETC",
            CoinType::BitcoinCash => "BCH",
            CoinType::BinanceCoin => "BNB",
            CoinType::Solana => "SOL",
            CoinType::Cardano => "ADA",
            CoinType::Polkadot => "DOT",
            CoinType::Cosmos => "ATOM",
            CoinType::Tron => "TRX",
            CoinType::Custom(_) => "CUSTOM",
        }
    }

    /// Returns the full name of this coin type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::CoinType;
    ///
    /// assert_eq!(CoinType::Bitcoin.name(), "Bitcoin");
    /// assert_eq!(CoinType::Ethereum.name(), "Ethereum");
    /// ```
    pub const fn name(&self) -> &'static str {
        match self {
            CoinType::Bitcoin => "Bitcoin",
            CoinType::BitcoinTestnet => "Bitcoin Testnet",
            CoinType::Litecoin => "Litecoin",
            CoinType::Dogecoin => "Dogecoin",
            CoinType::Dash => "Dash",
            CoinType::Ethereum => "Ethereum",
            CoinType::EthereumClassic => "Ethereum Classic",
            CoinType::BitcoinCash => "Bitcoin Cash",
            CoinType::BinanceCoin => "Binance Coin",
            CoinType::Solana => "Solana",
            CoinType::Cardano => "Cardano",
            CoinType::Polkadot => "Polkadot",
            CoinType::Cosmos => "Cosmos",
            CoinType::Tron => "Tron",
            CoinType::Custom(_) => "Custom",
        }
    }

    /// Returns `true` if this is a testnet coin type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::CoinType;
    ///
    /// assert!(CoinType::BitcoinTestnet.is_testnet());
    /// assert!(!CoinType::Bitcoin.is_testnet());
    /// assert!(!CoinType::Ethereum.is_testnet());
    /// ```
    pub const fn is_testnet(&self) -> bool {
        matches!(self, CoinType::BitcoinTestnet)
    }

    /// Returns `true` if this coin type uses EVM-compatible address derivation.
    ///
    /// EVM-compatible chains derive addresses from the public key using Keccak-256
    /// hashing. This includes:
    /// - Ethereum and all Ethereum-based chains (Polygon, Arbitrum, Optimism, etc.)
    /// - Ethereum Classic
    /// - Binance Smart Chain (BSC)
    /// - Tron (uses modified EVM)
    ///
    /// Note: Most EVM chains (Polygon, Avalanche C-Chain, Arbitrum, etc.) use
    /// Ethereum's coin type (60), so they're covered by `CoinType::Ethereum`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::CoinType;
    ///
    /// assert!(CoinType::Ethereum.is_evm_compatible());
    /// assert!(CoinType::EthereumClassic.is_evm_compatible());
    /// assert!(CoinType::BinanceCoin.is_evm_compatible());
    /// assert!(CoinType::Tron.is_evm_compatible());
    /// assert!(!CoinType::Bitcoin.is_evm_compatible());
    /// assert!(!CoinType::Solana.is_evm_compatible());
    /// ```
    pub const fn is_evm_compatible(&self) -> bool {
        matches!(
            self,
            CoinType::Ethereum | CoinType::EthereumClassic | CoinType::BinanceCoin | CoinType::Tron
        )
    }

    /// Returns the default purpose for this coin type.
    ///
    /// Different cryptocurrencies may have different default address formats:
    /// - Bitcoin: Defaults to BIP-84 (Native SegWit)
    /// - Ethereum: Only uses BIP-44 (no SegWit variants)
    /// - Others: Default to BIP-44
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::{CoinType, Purpose};
    ///
    /// assert_eq!(CoinType::Bitcoin.default_purpose(), Purpose::BIP84);
    /// assert_eq!(CoinType::Ethereum.default_purpose(), Purpose::BIP44);
    /// assert_eq!(CoinType::Litecoin.default_purpose(), Purpose::BIP84);
    /// ```
    pub const fn default_purpose(&self) -> Purpose {
        match self {
            // Bitcoin and Bitcoin-like coins default to native SegWit (BIP-84)
            CoinType::Bitcoin | CoinType::BitcoinTestnet | CoinType::Litecoin => Purpose::BIP84,
            // All other coins use standard BIP-44
            _ => Purpose::BIP44,
        }
    }
}

impl TryFrom<u32> for CoinType {
    type Error = Error;

    /// Attempts to convert a u32 SLIP-44 index to a CoinType.
    ///
    /// If the index matches a known coin, returns the specific variant.
    /// Otherwise, returns `Custom(index)` for any valid u32.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::CoinType;
    ///
    /// // Known coins
    /// assert_eq!(CoinType::try_from(0).unwrap(), CoinType::Bitcoin);
    /// assert_eq!(CoinType::try_from(60).unwrap(), CoinType::Ethereum);
    ///
    /// // Unknown coins become Custom
    /// assert_eq!(CoinType::try_from(999).unwrap(), CoinType::Custom(999));
    /// ```
    fn try_from(index: u32) -> Result<Self> {
        Ok(match index {
            0 => CoinType::Bitcoin,
            1 => CoinType::BitcoinTestnet,
            2 => CoinType::Litecoin,
            3 => CoinType::Dogecoin,
            5 => CoinType::Dash,
            60 => CoinType::Ethereum,
            61 => CoinType::EthereumClassic,
            118 => CoinType::Cosmos,
            145 => CoinType::BitcoinCash,
            195 => CoinType::Tron,
            354 => CoinType::Polkadot,
            501 => CoinType::Solana,
            714 => CoinType::BinanceCoin,
            1815 => CoinType::Cardano,
            _ => CoinType::Custom(index),
        })
    }
}

impl From<CoinType> for u32 {
    /// Converts a CoinType to its SLIP-44 index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::CoinType;
    ///
    /// let index: u32 = CoinType::Bitcoin.into();
    /// assert_eq!(index, 0);
    ///
    /// let index: u32 = CoinType::Ethereum.into();
    /// assert_eq!(index, 60);
    ///
    /// let index: u32 = CoinType::Custom(999).into();
    /// assert_eq!(index, 999);
    /// ```
    fn from(coin: CoinType) -> Self {
        coin.index()
    }
}

impl fmt::Display for CoinType {
    /// Formats the coin type for display using its symbol.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::CoinType;
    ///
    /// assert_eq!(CoinType::Bitcoin.to_string(), "BTC");
    /// assert_eq!(CoinType::Ethereum.to_string(), "ETH");
    /// assert_eq!(CoinType::Custom(999).to_string(), "CUSTOM(999)");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoinType::Custom(index) => write!(f, "CUSTOM({})", index),
            _ => write!(f, "{}", self.symbol()),
        }
    }
}

#[cfg(test)]
mod cointype_tests {
    use super::*;

    #[test]
    fn test_cointype_indices() {
        assert_eq!(CoinType::Bitcoin.index(), 0);
        assert_eq!(CoinType::BitcoinTestnet.index(), 1);
        assert_eq!(CoinType::Litecoin.index(), 2);
        assert_eq!(CoinType::Dogecoin.index(), 3);
        assert_eq!(CoinType::Dash.index(), 5);
        assert_eq!(CoinType::Ethereum.index(), 60);
        assert_eq!(CoinType::EthereumClassic.index(), 61);
        assert_eq!(CoinType::BitcoinCash.index(), 145);
        assert_eq!(CoinType::Cosmos.index(), 118);
        assert_eq!(CoinType::Tron.index(), 195);
        assert_eq!(CoinType::Polkadot.index(), 354);
        assert_eq!(CoinType::Solana.index(), 501);
        assert_eq!(CoinType::BinanceCoin.index(), 714);
        assert_eq!(CoinType::Cardano.index(), 1815);
        assert_eq!(CoinType::Custom(999).index(), 999);
    }

    #[test]
    fn test_cointype_symbols() {
        assert_eq!(CoinType::Bitcoin.symbol(), "BTC");
        assert_eq!(CoinType::BitcoinTestnet.symbol(), "tBTC");
        assert_eq!(CoinType::Litecoin.symbol(), "LTC");
        assert_eq!(CoinType::Dogecoin.symbol(), "DOGE");
        assert_eq!(CoinType::Dash.symbol(), "DASH");
        assert_eq!(CoinType::Ethereum.symbol(), "ETH");
        assert_eq!(CoinType::EthereumClassic.symbol(), "ETC");
        assert_eq!(CoinType::BitcoinCash.symbol(), "BCH");
        assert_eq!(CoinType::BinanceCoin.symbol(), "BNB");
        assert_eq!(CoinType::Solana.symbol(), "SOL");
        assert_eq!(CoinType::Cardano.symbol(), "ADA");
        assert_eq!(CoinType::Polkadot.symbol(), "DOT");
        assert_eq!(CoinType::Cosmos.symbol(), "ATOM");
        assert_eq!(CoinType::Tron.symbol(), "TRX");
        assert_eq!(CoinType::Custom(123).symbol(), "CUSTOM");
    }

    #[test]
    fn test_cointype_names() {
        assert_eq!(CoinType::Bitcoin.name(), "Bitcoin");
        assert_eq!(CoinType::BitcoinTestnet.name(), "Bitcoin Testnet");
        assert_eq!(CoinType::Litecoin.name(), "Litecoin");
        assert_eq!(CoinType::Dogecoin.name(), "Dogecoin");
        assert_eq!(CoinType::Dash.name(), "Dash");
        assert_eq!(CoinType::Ethereum.name(), "Ethereum");
        assert_eq!(CoinType::EthereumClassic.name(), "Ethereum Classic");
        assert_eq!(CoinType::BitcoinCash.name(), "Bitcoin Cash");
        assert_eq!(CoinType::BinanceCoin.name(), "Binance Coin");
        assert_eq!(CoinType::Solana.name(), "Solana");
        assert_eq!(CoinType::Cardano.name(), "Cardano");
        assert_eq!(CoinType::Polkadot.name(), "Polkadot");
        assert_eq!(CoinType::Cosmos.name(), "Cosmos");
        assert_eq!(CoinType::Tron.name(), "Tron");
        assert_eq!(CoinType::Custom(456).name(), "Custom");
    }

    #[test]
    fn test_cointype_custom() {
        let custom = CoinType::Custom(128); // Monero
        assert_eq!(custom.index(), 128);
        assert_eq!(custom.symbol(), "CUSTOM");
        assert_eq!(custom.name(), "Custom");
    }

    #[test]
    fn test_cointype_equality() {
        assert_eq!(CoinType::Bitcoin, CoinType::Bitcoin);
        assert_eq!(CoinType::Ethereum, CoinType::Ethereum);
        assert_ne!(CoinType::Bitcoin, CoinType::Ethereum);

        assert_eq!(CoinType::Custom(100), CoinType::Custom(100));
        assert_ne!(CoinType::Custom(100), CoinType::Custom(101));
    }

    #[test]
    fn test_cointype_clone() {
        let coin = CoinType::Bitcoin;
        let cloned = coin;
        assert_eq!(coin, cloned);

        let custom = CoinType::Custom(999);
        let cloned_custom = custom;
        assert_eq!(custom, cloned_custom);
    }

    #[test]
    fn test_cointype_debug() {
        assert_eq!(format!("{:?}", CoinType::Bitcoin), "Bitcoin");
        assert_eq!(format!("{:?}", CoinType::Ethereum), "Ethereum");
        assert_eq!(format!("{:?}", CoinType::Custom(123)), "Custom(123)");
    }

    #[test]
    fn test_major_coins_coverage() {
        // Ensure all major coins are accessible
        let _btc = CoinType::Bitcoin;
        let _eth = CoinType::Ethereum;
        let _ltc = CoinType::Litecoin;
        let _doge = CoinType::Dogecoin;
        let _bch = CoinType::BitcoinCash;
        let _bnb = CoinType::BinanceCoin;
        let _sol = CoinType::Solana;
        let _ada = CoinType::Cardano;
        let _dot = CoinType::Polkadot;
        let _atom = CoinType::Cosmos;
    }

    #[test]
    fn test_slip44_compliance() {
        // Verify indices match SLIP-44 registry
        // https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        assert_eq!(CoinType::Bitcoin.index(), 0);
        assert_eq!(CoinType::BitcoinTestnet.index(), 1);
        assert_eq!(CoinType::Litecoin.index(), 2);
        assert_eq!(CoinType::Dogecoin.index(), 3);
        assert_eq!(CoinType::Ethereum.index(), 60);
    }

    #[test]
    fn test_cointype_try_from_known() {
        // Test known coins
        assert_eq!(CoinType::try_from(0).unwrap(), CoinType::Bitcoin);
        assert_eq!(CoinType::try_from(1).unwrap(), CoinType::BitcoinTestnet);
        assert_eq!(CoinType::try_from(2).unwrap(), CoinType::Litecoin);
        assert_eq!(CoinType::try_from(3).unwrap(), CoinType::Dogecoin);
        assert_eq!(CoinType::try_from(5).unwrap(), CoinType::Dash);
        assert_eq!(CoinType::try_from(60).unwrap(), CoinType::Ethereum);
        assert_eq!(CoinType::try_from(61).unwrap(), CoinType::EthereumClassic);
        assert_eq!(CoinType::try_from(118).unwrap(), CoinType::Cosmos);
        assert_eq!(CoinType::try_from(145).unwrap(), CoinType::BitcoinCash);
        assert_eq!(CoinType::try_from(195).unwrap(), CoinType::Tron);
        assert_eq!(CoinType::try_from(354).unwrap(), CoinType::Polkadot);
        assert_eq!(CoinType::try_from(501).unwrap(), CoinType::Solana);
        assert_eq!(CoinType::try_from(714).unwrap(), CoinType::BinanceCoin);
        assert_eq!(CoinType::try_from(1815).unwrap(), CoinType::Cardano);
    }

    #[test]
    fn test_cointype_try_from_unknown() {
        // Unknown coins should become Custom
        assert_eq!(CoinType::try_from(999).unwrap(), CoinType::Custom(999));
        assert_eq!(CoinType::try_from(128).unwrap(), CoinType::Custom(128)); // Monero
        assert_eq!(CoinType::try_from(133).unwrap(), CoinType::Custom(133)); // Zcash
        assert_eq!(CoinType::try_from(9999).unwrap(), CoinType::Custom(9999));
    }

    #[test]
    fn test_cointype_into_u32() {
        let index: u32 = CoinType::Bitcoin.into();
        assert_eq!(index, 0);

        let index: u32 = CoinType::Ethereum.into();
        assert_eq!(index, 60);

        let index: u32 = CoinType::Custom(999).into();
        assert_eq!(index, 999);
    }

    #[test]
    fn test_cointype_round_trip() {
        // Test round-trip conversion for known coins
        for index in [0, 1, 2, 3, 5, 60, 61, 118, 145, 195, 354, 501, 714, 1815] {
            let coin = CoinType::try_from(index).unwrap();
            let back: u32 = coin.into();
            assert_eq!(back, index);
        }

        // Test round-trip for custom coins
        for index in [999, 128, 133, 5000] {
            let coin = CoinType::try_from(index).unwrap();
            let back: u32 = coin.into();
            assert_eq!(back, index);
        }
    }

    #[test]
    fn test_cointype_display() {
        assert_eq!(CoinType::Bitcoin.to_string(), "BTC");
        assert_eq!(CoinType::Ethereum.to_string(), "ETH");
        assert_eq!(CoinType::Litecoin.to_string(), "LTC");
        assert_eq!(CoinType::BinanceCoin.to_string(), "BNB");
        assert_eq!(CoinType::Custom(999).to_string(), "CUSTOM(999)");
        assert_eq!(CoinType::Custom(128).to_string(), "CUSTOM(128)");
    }

    #[test]
    fn test_cointype_is_testnet() {
        assert!(CoinType::BitcoinTestnet.is_testnet());

        assert!(!CoinType::Bitcoin.is_testnet());
        assert!(!CoinType::Ethereum.is_testnet());
        assert!(!CoinType::Litecoin.is_testnet());
        assert!(!CoinType::Custom(1).is_testnet());
    }

    #[test]
    fn test_cointype_default_purpose() {
        // Bitcoin-like coins default to BIP-84 (native SegWit)
        assert_eq!(CoinType::Bitcoin.default_purpose(), Purpose::BIP84);
        assert_eq!(CoinType::BitcoinTestnet.default_purpose(), Purpose::BIP84);
        assert_eq!(CoinType::Litecoin.default_purpose(), Purpose::BIP84);

        // All other coins default to BIP-44
        assert_eq!(CoinType::Ethereum.default_purpose(), Purpose::BIP44);
        assert_eq!(CoinType::Dogecoin.default_purpose(), Purpose::BIP44);
        assert_eq!(CoinType::BitcoinCash.default_purpose(), Purpose::BIP44);
        assert_eq!(CoinType::Solana.default_purpose(), Purpose::BIP44);
        assert_eq!(CoinType::Cardano.default_purpose(), Purpose::BIP44);
        assert_eq!(CoinType::Custom(999).default_purpose(), Purpose::BIP44);
    }

    #[test]
    fn test_cointype_conversions_are_infallible() {
        // TryFrom should never fail for any u32 value
        assert!(CoinType::try_from(0).is_ok());
        assert!(CoinType::try_from(u32::MAX).is_ok());
        assert!(CoinType::try_from(999999).is_ok());
    }
}
