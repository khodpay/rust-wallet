//! Error handling for BIP-44 multi-account hierarchy operations.
//!
//! This module provides comprehensive error types for all BIP-44-related operations,
//! including path construction, validation, parsing, and account management.
//!
//! # Error Types
//!
//! The main [`Error`] enum covers all possible failure modes:
//! - **Purpose errors**: Invalid purpose values (must be 44, 49, 84, or 86)
//! - **Coin type errors**: Invalid or unrecognized cryptocurrency types
//! - **Chain errors**: Invalid chain values (must be 0 or 1)
//! - **Path errors**: Invalid path structure, depth, or hardened levels
//! - **External errors**: Errors from BIP-32 operations
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip44::{Error, Result};
//!
//! // Creating and matching specific errors
//! let purpose_error = Error::InvalidPurpose { value: 99 };
//! match purpose_error {
//!     Error::InvalidPurpose { value } => {
//!         println!("Invalid purpose: {}", value);
//!     }
//!     _ => {}
//! }
//!
//! // Error equality comparison
//! let error1 = Error::InvalidChain { value: 2 };
//! let error2 = Error::InvalidChain { value: 2 };
//! assert_eq!(error1, error2);
//! ```

use thiserror::Error;

/// Comprehensive error types for BIP-44 multi-account hierarchy operations.
///
/// This enum represents all possible errors that can occur when working with
/// BIP-44 paths, from construction to validation and parsing.
///
/// # Error Categories
///
/// - **Type Validation**: [`InvalidPurpose`], [`InvalidCoinType`], [`InvalidChain`]
/// - **Index Validation**: [`InvalidAccount`], [`InvalidAddressIndex`]
/// - **Path Validation**: [`InvalidPath`], [`InvalidDepth`], [`InvalidHardenedLevel`]
/// - **Parsing**: [`ParseError`]
/// - **External Dependencies**: [`Bip32Error`]
///
/// [`InvalidPurpose`]: Error::InvalidPurpose
/// [`InvalidCoinType`]: Error::InvalidCoinType
/// [`InvalidChain`]: Error::InvalidChain
/// [`InvalidAccount`]: Error::InvalidAccount
/// [`InvalidAddressIndex`]: Error::InvalidAddressIndex
/// [`InvalidPath`]: Error::InvalidPath
/// [`InvalidDepth`]: Error::InvalidDepth
/// [`InvalidHardenedLevel`]: Error::InvalidHardenedLevel
/// [`ParseError`]: Error::ParseError
/// [`Bip32Error`]: Error::Bip32Error
#[derive(Debug, Error)]
pub enum Error {
    /// The provided purpose value is invalid.
    ///
    /// BIP-44 and related standards support only specific purpose values:
    /// - 44: BIP-44 (Legacy P2PKH addresses)
    /// - 49: BIP-49 (SegWit wrapped in P2SH)
    /// - 84: BIP-84 (Native SegWit)
    /// - 86: BIP-86 (Taproot)
    ///
    /// # Example
    /// ```rust
    /// # use khodpay_bip44::Error;
    /// let error = Error::InvalidPurpose { value: 99 };
    /// println!("{}", error); // "Invalid purpose value: 99. Valid values are 44, 49, 84, or 86"
    /// ```
    #[error("Invalid purpose value: {value}. Valid values are 44, 49, 84, or 86")]
    InvalidPurpose {
        /// The invalid purpose value provided
        value: u32,
    },

    /// The provided coin type is invalid.
    ///
    /// This error occurs when a coin type string or identifier cannot be
    /// recognized or validated according to SLIP-44 standards.
    ///
    /// # Example
    /// ```rust
    /// # use khodpay_bip44::Error;
    /// let error = Error::InvalidCoinType {
    ///     reason: "Unknown coin identifier".to_string()
    /// };
    /// ```
    #[error("Invalid coin type: {reason}")]
    InvalidCoinType {
        /// Detailed reason why the coin type is invalid
        reason: String,
    },

    /// The provided chain value is invalid.
    ///
    /// BIP-44 defines only two valid chain values:
    /// - 0: External chain (receiving addresses)
    /// - 1: Internal chain (change addresses)
    ///
    /// # Example
    /// ```rust
    /// # use khodpay_bip44::Error;
    /// let error = Error::InvalidChain { value: 2 };
    /// println!("{}", error); // "Invalid chain value: 2 (must be 0 for external or 1 for internal)"
    /// ```
    #[error("Invalid chain value: {value} (must be 0 for external or 1 for internal)")]
    InvalidChain {
        /// The invalid chain value provided
        value: u32,
    },

    /// The provided account index is invalid.
    ///
    /// Account indices must be valid u32 values and properly formatted for
    /// hardened derivation (< 2^31).
    #[error("Invalid account index: {reason}")]
    InvalidAccount {
        /// Detailed reason why the account index is invalid
        reason: String,
    },

    /// The provided address index is invalid.
    ///
    /// Address indices must be valid u32 values.
    #[error("Invalid address index: {reason}")]
    InvalidAddressIndex {
        /// Detailed reason why the address index is invalid
        reason: String,
    },

    /// The BIP-44 path structure or format is invalid.
    ///
    /// This is a generic path error for issues that don't fit other categories.
    #[error("Invalid path: {reason}")]
    InvalidPath {
        /// Detailed reason why the path is invalid
        reason: String,
    },

    /// The path depth is not exactly 5 levels.
    ///
    /// BIP-44 paths must have exactly 5 levels:
    /// m / purpose' / coin_type' / account' / chain / address_index
    ///
    /// # Example
    /// ```rust
    /// # use khodpay_bip44::Error;
    /// let error = Error::InvalidDepth { depth: 3 };
    /// println!("{}", error);
    /// ```
    #[error("Invalid path depth: expected 5 levels (m/purpose'/coin_type'/account'/chain/address_index), got {depth}")]
    InvalidDepth {
        /// The actual depth that was encountered
        depth: usize,
    },

    /// The hardened derivation levels are incorrect.
    ///
    /// In BIP-44, the first 3 levels (purpose, coin_type, account) MUST use
    /// hardened derivation, while the last 2 levels (chain, address_index)
    /// MUST use normal derivation.
    ///
    /// # Example
    /// ```rust
    /// # use khodpay_bip44::Error;
    /// let error = Error::InvalidHardenedLevel {
    ///     reason: "Purpose level must be hardened".to_string()
    /// };
    /// ```
    #[error("Invalid hardened level: {reason}")]
    InvalidHardenedLevel {
        /// Detailed reason why the hardened levels are invalid
        reason: String,
    },

    /// Error from BIP-32 operations.
    ///
    /// This occurs when underlying BIP-32 key derivation operations fail.
    /// The error is automatically converted from [`khodpay_bip32::Error`].
    #[error("BIP-32 error: {0}")]
    Bip32Error(#[from] khodpay_bip32::Error),

    /// Path string parsing error.
    ///
    /// This occurs when parsing a BIP-44 path from a string fails due to
    /// invalid format, syntax, or structure.
    ///
    /// # Example
    /// ```rust
    /// # use khodpay_bip44::Error;
    /// let error = Error::ParseError {
    ///     reason: "Missing 'm' prefix".to_string()
    /// };
    /// ```
    #[error("Parse error: {reason}")]
    ParseError {
        /// Detailed reason why parsing failed
        reason: String,
    },

    /// Invalid seed provided for wallet creation.
    ///
    /// # Example
    /// ```rust
    /// # use khodpay_bip44::Error;
    /// let error = Error::InvalidSeed("Seed cannot be empty".to_string());
    /// ```
    #[error("Invalid seed: {0}")]
    InvalidSeed(String),

    /// Invalid mnemonic phrase provided.
    ///
    /// # Example
    /// ```rust
    /// # use khodpay_bip44::Error;
    /// let error = Error::InvalidMnemonic("Invalid word count".to_string());
    /// ```
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Key derivation error.
    ///
    /// # Example
    /// ```rust
    /// # use khodpay_bip44::Error;
    /// let error = Error::KeyDerivation("Failed to derive key".to_string());
    /// ```
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),
}

/// Custom equality implementation for [`Error`].
///
/// This implementation allows comparing errors for equality, which is useful
/// in tests and error matching.
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Error::InvalidPurpose { value: v1 }, Error::InvalidPurpose { value: v2 }) => v1 == v2,
            (Error::InvalidCoinType { reason: r1 }, Error::InvalidCoinType { reason: r2 }) => {
                r1 == r2
            }
            (Error::InvalidChain { value: v1 }, Error::InvalidChain { value: v2 }) => v1 == v2,
            (Error::InvalidAccount { reason: r1 }, Error::InvalidAccount { reason: r2 }) => {
                r1 == r2
            }
            (
                Error::InvalidAddressIndex { reason: r1 },
                Error::InvalidAddressIndex { reason: r2 },
            ) => r1 == r2,
            (Error::InvalidPath { reason: r1 }, Error::InvalidPath { reason: r2 }) => r1 == r2,
            (Error::InvalidDepth { depth: d1 }, Error::InvalidDepth { depth: d2 }) => d1 == d2,
            (
                Error::InvalidHardenedLevel { reason: r1 },
                Error::InvalidHardenedLevel { reason: r2 },
            ) => r1 == r2,
            (Error::Bip32Error(e1), Error::Bip32Error(e2)) => e1 == e2,
            (Error::ParseError { reason: r1 }, Error::ParseError { reason: r2 }) => r1 == r2,
            (Error::InvalidSeed(s1), Error::InvalidSeed(s2)) => s1 == s2,
            (Error::InvalidMnemonic(m1), Error::InvalidMnemonic(m2)) => m1 == m2,
            (Error::KeyDerivation(k1), Error::KeyDerivation(k2)) => k1 == k2,
            _ => false,
        }
    }
}

/// Marker trait indicating that [`Error`] can be compared for equality.
impl Eq for Error {}

/// Convenient type alias for [`std::result::Result`] with our [`Error`] type.
///
/// This allows using `Result<T>` instead of `Result<T, Error>` throughout
/// the codebase, making function signatures cleaner and more readable.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::{Result, Error};
///
/// fn validate_chain(chain: u32) -> Result<()> {
///     if chain > 1 {
///         return Err(Error::InvalidChain { value: chain });
///     }
///     Ok(())
/// }
/// ```
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_purpose_error() {
        let error = Error::InvalidPurpose { value: 99 };
        assert_eq!(
            error.to_string(),
            "Invalid purpose value: 99. Valid values are 44, 49, 84, or 86"
        );
    }

    #[test]
    fn test_invalid_chain_error() {
        let error = Error::InvalidChain { value: 2 };
        assert_eq!(
            error.to_string(),
            "Invalid chain value: 2 (must be 0 for external or 1 for internal)"
        );
    }

    #[test]
    fn test_invalid_depth_error() {
        let error = Error::InvalidDepth { depth: 3 };
        assert_eq!(
            error.to_string(),
            "Invalid path depth: expected 5 levels (m/purpose'/coin_type'/account'/chain/address_index), got 3"
        );
    }

    #[test]
    fn test_error_equality() {
        let error1 = Error::InvalidChain { value: 2 };
        let error2 = Error::InvalidChain { value: 2 };
        let error3 = Error::InvalidChain { value: 3 };

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    #[test]
    fn test_invalid_coin_type_error() {
        let error = Error::InvalidCoinType {
            reason: "Unknown coin".to_string(),
        };
        assert_eq!(error.to_string(), "Invalid coin type: Unknown coin");
    }

    #[test]
    fn test_parse_error() {
        let error = Error::ParseError {
            reason: "Missing prefix".to_string(),
        };
        assert_eq!(error.to_string(), "Parse error: Missing prefix");
    }

    #[test]
    fn test_invalid_hardened_level_error() {
        let error = Error::InvalidHardenedLevel {
            reason: "Purpose must be hardened".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Invalid hardened level: Purpose must be hardened"
        );
    }
}
