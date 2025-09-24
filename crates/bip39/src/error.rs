//! Error handling for BIP39 mnemonic operations.
//!
//! This module provides comprehensive error types for all BIP39-related operations,
//! including mnemonic generation, validation, and seed derivation.
//!
//! # Error Types
//!
//! The main [`Error`] enum covers all possible failure modes:
//! - **Validation errors**: Invalid entropy, word count, or mnemonic phrases
//! - **Word errors**: Invalid words or checksum failures  
//! - **External errors**: Random number generation and underlying BIP39 crate errors
//!
//! # Examples
//!
//! ```rust
//! use bip39::{Error, Result};
//!
//! // Creating and matching specific errors
//! let entropy_error = Error::InvalidEntropyLength { length: 10 };
//! match entropy_error {
//!     Error::InvalidEntropyLength { length } => {
//!         println!("Entropy too short: {} bytes", length);
//!     }
//!     _ => {}
//! }
//!
//! // Error equality comparison  
//! let error1 = Error::InvalidWordCount { count: 13 };
//! let error2 = Error::InvalidWordCount { count: 13 };
//! assert_eq!(error1, error2);
//! ```

use thiserror::Error;

/// Comprehensive error types for BIP39 mnemonic operations.
///
/// This enum represents all possible errors that can occur when working with
/// BIP39 mnemonics, from entropy generation to seed derivation.
///
/// # Error Categories
///
/// - **Input Validation**: [`InvalidEntropyLength`], [`InvalidWordCount`], [`InvalidMnemonic`]
/// - **Mnemonic Validation**: [`InvalidWord`], [`InvalidChecksum`]  
/// - **External Dependencies**: [`RandomGeneration`], [`Bip39Error`]
///
/// [`InvalidEntropyLength`]: Error::InvalidEntropyLength
/// [`InvalidWordCount`]: Error::InvalidWordCount
/// [`InvalidMnemonic`]: Error::InvalidMnemonic
/// [`InvalidWord`]: Error::InvalidWord
/// [`InvalidChecksum`]: Error::InvalidChecksum
/// [`RandomGeneration`]: Error::RandomGeneration
/// [`Bip39Error`]: Error::Bip39Error
#[derive(Debug, Error)]
pub enum Error {
    /// The provided entropy has an invalid length.
    ///
    /// BIP39 requires entropy to be one of the following lengths:
    /// - 16 bytes (128 bits) → 12 words
    /// - 20 bytes (160 bits) → 15 words  
    /// - 24 bytes (192 bits) → 18 words
    /// - 28 bytes (224 bits) → 21 words
    /// - 32 bytes (256 bits) → 24 words
    ///
    /// # Example
    /// ```rust
    /// # use bip39::Error;
    /// let error = Error::InvalidEntropyLength { length: 10 };
    /// println!("{}", error); // "Invalid entropy length: 10 bytes. Valid lengths are..."
    /// ```
    #[error("Invalid entropy length: {length} bytes. Valid lengths are 16, 20, 24, 28, or 32 bytes")]
    InvalidEntropyLength { 
        /// The actual length of the invalid entropy in bytes
        length: usize 
    },

    /// The provided mnemonic phrase is invalid.
    ///
    /// This error occurs when a mnemonic phrase fails general validation,
    /// such as having the wrong format, length, or structure.
    ///
    /// # Example
    /// ```rust
    /// # use bip39::Error;
    /// let error = Error::InvalidMnemonic { 
    ///     reason: "Too few words".to_string() 
    /// };
    /// ```
    #[error("Invalid mnemonic phrase: {reason}")]
    InvalidMnemonic { 
        /// Detailed reason why the mnemonic is invalid
        reason: String 
    },

    /// The provided word count is not supported.
    ///
    /// BIP39 supports only specific word counts that correspond to
    /// valid entropy lengths. See [`InvalidEntropyLength`] for the mapping.
    ///
    /// [`InvalidEntropyLength`]: Error::InvalidEntropyLength
    #[error("Invalid word count: {count}. Valid counts are 12, 15, 18, 21, or 24 words")]
    InvalidWordCount { 
        /// The invalid word count provided
        count: usize 
    },

    /// A word in the mnemonic phrase is not in the BIP39 word list.
    ///
    /// Each word in a BIP39 mnemonic must be from the official 2048-word list.
    /// This error provides both the invalid word and its position for debugging.
    ///
    /// # Example
    /// ```rust
    /// # use bip39::Error;
    /// let error = Error::InvalidWord {
    ///     word: "invalidword".to_string(),
    ///     position: 5,
    /// };
    /// println!("{}", error); // "Invalid word 'invalidword' at position 5"
    /// ```
    #[error("Invalid word '{word}' at position {position}")]
    InvalidWord { 
        /// The invalid word that was found
        word: String, 
        /// Zero-based position of the invalid word in the phrase
        position: usize 
    },

    /// The mnemonic phrase has an invalid checksum.
    ///
    /// BIP39 mnemonics include a checksum derived from the entropy.
    /// This error occurs when the checksum verification fails,
    /// indicating the mnemonic may be corrupted or incorrectly generated.
    #[error("Invalid checksum for mnemonic phrase")]
    InvalidChecksum,

    /// Error occurred during random number generation.
    ///
    /// This error is automatically converted from [`rand::Error`] and
    /// indicates a failure in the random number generator used for
    /// entropy generation.
    #[error("Random number generation failed")]
    RandomGeneration,

    /// Error from the underlying BIP39 crate.
    ///
    /// This error wraps errors from the external `bip39` crate that
    /// we use for some low-level operations.
    #[error("BIP39 error: {message}")]
    Bip39Error { 
        /// Error message from the underlying BIP39 crate
        message: String 
    },
}

/// Custom equality implementation for [`enum@Error`].
///
/// This implementation allows comparing errors for equality, which is useful
/// in tests and error matching. For errors containing external types 
/// (like [`rand::Error`] or [`bip39_upstream::Error`]), we compare only
/// by error type since the wrapped errors may not implement [`PartialEq`].
///
/// # Examples
///
/// ```rust
/// # use bip39::Error;
/// let error1 = Error::InvalidWordCount { count: 12 };
/// let error2 = Error::InvalidWordCount { count: 12 };
/// let error3 = Error::InvalidWordCount { count: 15 };
///
/// assert_eq!(error1, error2);  // Same variant and data
/// assert_ne!(error1, error3);  // Same variant, different data
/// ```
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Error::InvalidEntropyLength { length: l1 }, Error::InvalidEntropyLength { length: l2 }) => l1 == l2,
            (Error::InvalidMnemonic { reason: r1 }, Error::InvalidMnemonic { reason: r2 }) => r1 == r2,
            (Error::InvalidWordCount { count: c1 }, Error::InvalidWordCount { count: c2 }) => c1 == c2,
            (Error::InvalidWord { word: w1, position: p1 }, Error::InvalidWord { word: w2, position: p2 }) => w1 == w2 && p1 == p2,
            (Error::InvalidChecksum, Error::InvalidChecksum) => true,
            (Error::RandomGeneration, Error::RandomGeneration) => true,
            (Error::Bip39Error { message: m1 }, Error::Bip39Error { message: m2 }) => m1 == m2,
            _ => false,
        }
    }
}

/// Marker trait indicating that [`enum@Error`] can be compared for equality.
///
/// This is automatically implemented since we provide [`PartialEq`].
impl Eq for Error {}

/// Convert from `rand::Error` to our `Error` type.
impl From<rand::Error> for Error {
    fn from(_error: rand::Error) -> Self {
        Error::RandomGeneration
    }
}

/// Convert from `bip39_upstream::Error` to our `Error` type.
impl From<bip39_upstream::Error> for Error {
    fn from(error: bip39_upstream::Error) -> Self {
        Error::Bip39Error {
            message: error.to_string(),
        }
    }
}

/// Convenient type alias for [`std::result::Result`] with our [`enum@Error`] type.
///
/// This allows using `Result<T>` instead of `Result<T, Error>` throughout
/// the codebase, making function signatures cleaner and more readable.
///
/// # Examples
///
/// ```rust
/// use bip39::{Result, Error};
///
/// fn validate_entropy(entropy: &[u8]) -> Result<()> {
///     if entropy.len() != 32 {
///         return Err(Error::InvalidEntropyLength { 
///             length: entropy.len() 
///         });
///     }
///     Ok(())
/// }
/// ```
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = Error::InvalidEntropyLength { length: 10 };
        assert_eq!(
            error.to_string(),
            "Invalid entropy length: 10 bytes. Valid lengths are 16, 20, 24, 28, or 32 bytes"
        );
    }

    #[test]
    fn test_error_equality() {
        let error1 = Error::InvalidWordCount { count: 13 };
        let error2 = Error::InvalidWordCount { count: 13 };
        let error3 = Error::InvalidWordCount { count: 14 };

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    #[test]
    fn test_invalid_mnemonic_error() {
        let error = Error::InvalidMnemonic {
            reason: "Too short".to_string(),
        };
        assert_eq!(error.to_string(), "Invalid mnemonic phrase: Too short");
    }

    #[test]
    fn test_invalid_word_error() {
        let error = Error::InvalidWord {
            word: "invalidword".to_string(),
            position: 5,
        };
        assert_eq!(
            error.to_string(),
            "Invalid word 'invalidword' at position 5"
        );
    }

    #[test]
    fn test_invalid_checksum_error() {
        let error = Error::InvalidChecksum;
        assert_eq!(error.to_string(), "Invalid checksum for mnemonic phrase");
    }
}
