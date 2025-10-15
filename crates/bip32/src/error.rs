//! Error handling for BIP32 hierarchical deterministic wallet operations.
//!
//! This module provides comprehensive error types for all BIP32-related operations,
//! including key generation, derivation, serialization, and deserialization.
//!
//! # Error Types
//!
//! The main [`enum@Error`] enum covers all possible failure modes:
//! - **Seed errors**: Invalid seed length
//! - **Key errors**: Invalid keys, zero keys, key overflow
//! - **Derivation errors**: Invalid paths, hardened derivation from public keys
//! - **Serialization errors**: Invalid format, checksum, version bytes
//! - **Cryptographic errors**: Invalid curve points, HMAC failures
//!
//! # Examples
//!
//! ```rust
//! use bip32::{Error, Result};
//!
//! // Creating and matching specific errors
//! let seed_error = Error::InvalidSeedLength { length: 10 };
//! match seed_error {
//!     Error::InvalidSeedLength { length } => {
//!         println!("Seed too short: {} bytes", length);
//!     }
//!     _ => {}
//! }
//! ```

use thiserror::Error;

/// Comprehensive error types for BIP32 hierarchical deterministic wallet operations.
///
/// This enum represents all possible errors that can occur when working with
/// BIP32 extended keys, from seed generation to key derivation.
///
/// # Error Categories
///
/// - **Seed Validation**: [`InvalidSeedLength`]
/// - **Key Validation**: [`InvalidPrivateKey`], [`InvalidPublicKey`], [`ZeroKey`], [`KeyOverflow`]
/// - **Derivation**: [`InvalidDerivationPath`], [`InvalidChildNumber`], [`HardenedDerivationFromPublicKey`], [`MaxDepthExceeded`]
/// - **Serialization**: [`InvalidExtendedKey`], [`InvalidChecksum`], [`InvalidVersionBytes`]
/// - **Cryptographic**: [`InvalidCurvePoint`], [`Secp256k1Error`]
/// - **External Dependencies**: [`Bip39Error`]
///
/// [`InvalidSeedLength`]: Error::InvalidSeedLength
/// [`InvalidPrivateKey`]: Error::InvalidPrivateKey
/// [`InvalidPublicKey`]: Error::InvalidPublicKey
/// [`ZeroKey`]: Error::ZeroKey
/// [`KeyOverflow`]: Error::KeyOverflow
/// [`InvalidDerivationPath`]: Error::InvalidDerivationPath
/// [`InvalidChildNumber`]: Error::InvalidChildNumber
/// [`HardenedDerivationFromPublicKey`]: Error::HardenedDerivationFromPublicKey
/// [`MaxDepthExceeded`]: Error::MaxDepthExceeded
/// [`InvalidExtendedKey`]: Error::InvalidExtendedKey
/// [`InvalidChecksum`]: Error::InvalidChecksum
/// [`InvalidVersionBytes`]: Error::InvalidVersionBytes
/// [`InvalidCurvePoint`]: Error::InvalidCurvePoint
/// [`Secp256k1Error`]: Error::Secp256k1Error
/// [`Bip39Error`]: Error::Bip39Error
#[derive(Debug, Error)]
pub enum Error {
    /// The provided seed has an invalid length.
    ///
    /// BIP32 recommends seeds between 128 and 512 bits (16-64 bytes).
    /// The most common seed length is 512 bits (64 bytes) from BIP39.
    ///
    /// # Example
    /// ```rust
    /// # use bip32::Error;
    /// let error = Error::InvalidSeedLength { length: 10 };
    /// println!("{}", error); // "Invalid seed length: 10 bytes..."
    /// ```
    #[error("Invalid seed length: {length} bytes. Seed must be between 16 and 64 bytes")]
    InvalidSeedLength {
        /// The actual length of the invalid seed in bytes
        length: usize,
    },

    /// The provided private key data is invalid.
    ///
    /// This occurs when private key bytes cannot form a valid secp256k1 private key.
    ///
    /// # Example
    /// ```rust
    /// # use bip32::Error;
    /// let error = Error::InvalidPrivateKey {
    ///     reason: "Key is all zeros".to_string()
    /// };
    /// ```
    #[error("Invalid private key: {reason}")]
    InvalidPrivateKey {
        /// Detailed reason why the private key is invalid
        reason: String,
    },

    /// The provided public key data is invalid.
    ///
    /// This occurs when public key bytes cannot form a valid secp256k1 public key,
    /// or when the point is not on the curve.
    #[error("Invalid public key: {reason}")]
    InvalidPublicKey {
        /// Detailed reason why the public key is invalid
        reason: String,
    },

    /// A derived key resulted in a zero value.
    ///
    /// Zero is not a valid private key in secp256k1. This is extremely rare
    /// but must be handled according to BIP32 spec (skip and try next index).
    #[error("Derived key is zero (invalid)")]
    ZeroKey,

    /// A derived key value is greater than or equal to the curve order.
    ///
    /// Private keys must be in the range [1, n-1] where n is the secp256k1 curve order.
    /// This is extremely rare but must be handled per BIP32 spec.
    #[error("Derived key exceeds curve order")]
    KeyOverflow,

    /// The provided derivation path is invalid.
    ///
    /// This occurs when parsing a path string that doesn't follow BIP32 format.
    /// Valid format: "m/0'/1/2'/3" where ' indicates hardened derivation.
    ///
    /// # Example
    /// ```rust
    /// # use bip32::Error;
    /// let error = Error::InvalidDerivationPath {
    ///     path: "invalid/path".to_string(),
    ///     reason: "Must start with 'm'".to_string(),
    /// };
    /// ```
    #[error("Invalid derivation path '{path}': {reason}")]
    InvalidDerivationPath {
        /// The invalid path string
        path: String,
        /// Detailed reason why the path is invalid
        reason: String,
    },

    /// The provided child number is invalid.
    ///
    /// Child numbers must be in the range [0, 2^32-1].
    #[error("Invalid child number: {number}")]
    InvalidChildNumber {
        /// The invalid child number
        number: u64,
    },

    /// Attempted to derive a hardened child from a public key.
    ///
    /// Hardened derivation requires the private key and cannot be performed
    /// on extended public keys. Only normal (non-hardened) derivation is
    /// possible from public keys.
    ///
    /// # Example
    /// ```rust
    /// # use bip32::Error;
    /// let error = Error::HardenedDerivationFromPublicKey { index: 2147483648 };
    /// println!("{}", error);
    /// ```
    #[error("Cannot perform hardened derivation (index {index}) from public key")]
    HardenedDerivationFromPublicKey {
        /// The hardened index that was attempted (>= 2^31)
        index: u32,
    },

    /// The derivation depth exceeds the maximum allowed depth.
    ///
    /// BIP32 uses a single byte for depth, limiting the maximum depth to 255.
    #[error("Maximum derivation depth exceeded: {depth}")]
    MaxDepthExceeded {
        /// The depth that was attempted
        depth: u8,
    },

    /// The extended key string is invalid.
    ///
    /// This occurs when deserializing an extended key (xprv/xpub) that has
    /// invalid format, length, or structure.
    #[error("Invalid extended key format: {reason}")]
    InvalidExtendedKey {
        /// Detailed reason why the extended key is invalid
        reason: String,
    },

    /// The extended key has an invalid checksum.
    ///
    /// Extended keys use Base58Check encoding with a 4-byte checksum.
    /// This error indicates the checksum verification failed.
    #[error("Invalid checksum in extended key")]
    InvalidChecksum,

    /// The extended key has invalid version bytes.
    ///
    /// Version bytes identify the network and key type (private/public).
    /// Valid versions: xprv (0x0488ADE4), xpub (0x0488B21E), tprv, tpub.
    #[error("Invalid version bytes: expected {expected:#x}, got {got:#x}")]
    InvalidVersionBytes {
        /// The expected version bytes
        expected: u32,
        /// The actual version bytes found
        got: u32,
    },

    /// The public key point is not on the secp256k1 curve.
    ///
    /// This is a critical cryptographic error that should not occur with
    /// properly generated keys.
    #[error("Invalid elliptic curve point")]
    InvalidCurvePoint,

    /// Error from the secp256k1 cryptographic library.
    ///
    /// This wraps errors from the underlying secp256k1 crate.
    #[error("secp256k1 error: {message}")]
    Secp256k1Error {
        /// Error message from the secp256k1 crate
        message: String,
    },

    /// Error from the BIP39 library.
    ///
    /// This occurs when integrating with BIP39 for mnemonic-to-seed conversion.
    #[error("BIP39 error: {0}")]
    Bip39Error(#[from] bip39::Error),

    /// Base58 decoding error.
    ///
    /// This occurs when decoding extended keys from Base58Check format.
    #[error("Base58 decode error: {message}")]
    Base58DecodeError {
        /// Error message from the base58 decoder
        message: String,
    },
}

/// Custom equality implementation for [`enum@Error`].
///
/// This implementation allows comparing errors for equality, which is useful
/// in tests and error matching.
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Error::InvalidSeedLength { length: l1 }, Error::InvalidSeedLength { length: l2 }) => {
                l1 == l2
            }
            (Error::InvalidPrivateKey { reason: r1 }, Error::InvalidPrivateKey { reason: r2 }) => {
                r1 == r2
            }
            (Error::InvalidPublicKey { reason: r1 }, Error::InvalidPublicKey { reason: r2 }) => {
                r1 == r2
            }
            (Error::ZeroKey, Error::ZeroKey) => true,
            (Error::KeyOverflow, Error::KeyOverflow) => true,
            (
                Error::InvalidDerivationPath {
                    path: p1,
                    reason: r1,
                },
                Error::InvalidDerivationPath {
                    path: p2,
                    reason: r2,
                },
            ) => p1 == p2 && r1 == r2,
            (
                Error::InvalidChildNumber { number: n1 },
                Error::InvalidChildNumber { number: n2 },
            ) => n1 == n2,
            (
                Error::HardenedDerivationFromPublicKey { index: i1 },
                Error::HardenedDerivationFromPublicKey { index: i2 },
            ) => i1 == i2,
            (Error::MaxDepthExceeded { depth: d1 }, Error::MaxDepthExceeded { depth: d2 }) => {
                d1 == d2
            }
            (
                Error::InvalidExtendedKey { reason: r1 },
                Error::InvalidExtendedKey { reason: r2 },
            ) => r1 == r2,
            (Error::InvalidChecksum, Error::InvalidChecksum) => true,
            (
                Error::InvalidVersionBytes {
                    expected: e1,
                    got: g1,
                },
                Error::InvalidVersionBytes {
                    expected: e2,
                    got: g2,
                },
            ) => e1 == e2 && g1 == g2,
            (Error::InvalidCurvePoint, Error::InvalidCurvePoint) => true,
            (Error::Secp256k1Error { message: m1 }, Error::Secp256k1Error { message: m2 }) => {
                m1 == m2
            }
            (Error::Bip39Error(e1), Error::Bip39Error(e2)) => e1 == e2,
            (
                Error::Base58DecodeError { message: m1 },
                Error::Base58DecodeError { message: m2 },
            ) => m1 == m2,
            _ => false,
        }
    }
}

/// Marker trait indicating that [`enum@Error`] can be compared for equality.
impl Eq for Error {}

/// Convert from `secp256k1::Error` to our `Error` type.
impl From<secp256k1::Error> for Error {
    fn from(error: secp256k1::Error) -> Self {
        Error::Secp256k1Error {
            message: error.to_string(),
        }
    }
}

/// Convert from `bs58::decode::Error` to our `Error` type.
impl From<bs58::decode::Error> for Error {
    fn from(error: bs58::decode::Error) -> Self {
        Error::Base58DecodeError {
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
/// use bip32::{Result, Error};
///
/// fn validate_seed(seed: &[u8]) -> Result<()> {
///     if seed.len() < 16 || seed.len() > 64 {
///         return Err(Error::InvalidSeedLength {
///             length: seed.len()
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
    fn test_invalid_seed_length_error() {
        let error = Error::InvalidSeedLength { length: 10 };
        assert_eq!(
            error.to_string(),
            "Invalid seed length: 10 bytes. Seed must be between 16 and 64 bytes"
        );
    }

    #[test]
    fn test_error_equality() {
        let error1 = Error::InvalidSeedLength { length: 10 };
        let error2 = Error::InvalidSeedLength { length: 10 };
        let error3 = Error::InvalidSeedLength { length: 20 };

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    #[test]
    fn test_invalid_private_key_error() {
        let error = Error::InvalidPrivateKey {
            reason: "All zeros".to_string(),
        };
        assert_eq!(error.to_string(), "Invalid private key: All zeros");
    }

    #[test]
    fn test_invalid_derivation_path_error() {
        let error = Error::InvalidDerivationPath {
            path: "x/0/1".to_string(),
            reason: "Must start with 'm'".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Invalid derivation path 'x/0/1': Must start with 'm'"
        );
    }

    #[test]
    fn test_hardened_derivation_from_public_key_error() {
        let error = Error::HardenedDerivationFromPublicKey { index: 2147483648 };
        assert_eq!(
            error.to_string(),
            "Cannot perform hardened derivation (index 2147483648) from public key"
        );
    }

    #[test]
    fn test_zero_key_error() {
        let error = Error::ZeroKey;
        assert_eq!(error.to_string(), "Derived key is zero (invalid)");
    }

    #[test]
    fn test_key_overflow_error() {
        let error = Error::KeyOverflow;
        assert_eq!(error.to_string(), "Derived key exceeds curve order");
    }

    #[test]
    fn test_invalid_checksum_error() {
        let error = Error::InvalidChecksum;
        assert_eq!(error.to_string(), "Invalid checksum in extended key");
    }

    #[test]
    fn test_invalid_version_bytes_error() {
        let error = Error::InvalidVersionBytes {
            expected: 0x0488ADE4,
            got: 0x0488B21E,
        };
        assert!(error.to_string().contains("0x488ade4"));
        assert!(error.to_string().contains("0x488b21e"));
    }

    #[test]
    fn test_max_depth_exceeded_error() {
        let error = Error::MaxDepthExceeded { depth: 255 };
        assert_eq!(error.to_string(), "Maximum derivation depth exceeded: 255");
    }
}
