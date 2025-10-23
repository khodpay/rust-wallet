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
        for purpose in [Purpose::BIP44, Purpose::BIP49, Purpose::BIP84, Purpose::BIP86] {
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
