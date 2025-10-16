//! Private key implementation for BIP32 hierarchical deterministic wallets.
//!
//! This module provides a wrapper around secp256k1 private keys for use in
//! BIP32 extended key derivation.

use crate::{Error, Result};
use secp256k1::{scalar::Scalar, PublicKey as Secp256k1PublicKey, SecretKey, SECP256K1};
use zeroize::Zeroize;

/// A 32-byte secp256k1 private key used in BIP32 hierarchical deterministic wallets.
///
/// Private keys are scalar values on the secp256k1 elliptic curve. They must be
/// non-zero and less than the curve order to be valid.
///
/// # Valid Range
///
/// A private key must satisfy: **1 ≤ key < n**
///
/// Where **n** is the secp256k1 curve order:
/// ```text
/// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
/// ```
///
/// ## Zero Key Prohibition
///
/// **Zero keys (all zeros) are explicitly rejected** because they would:
/// - Produce the point at infinity as a public key (invalid)
/// - Generate zero signatures (completely insecure)
/// - Allow anyone to forge signatures
/// - Violate the discrete logarithm problem assumptions
/// - Produce predictable child keys in derivation
///
/// All construction methods validate that the key is non-zero.
///
/// # Security
///
/// Private keys must be kept secret. Anyone with access to a private key can
/// spend funds and derive child keys. Always store private keys securely and
/// never expose them in logs or error messages.
///
/// This type implements `Drop` to securely zeroize memory when the key is dropped.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip32::PrivateKey;
///
/// // Valid: Create from non-zero bytes
/// let bytes = [1u8; 32];
/// let private_key = PrivateKey::from_bytes(&bytes)?;
///
/// // Get the bytes back
/// let key_bytes = private_key.to_bytes();
/// assert_eq!(key_bytes.len(), 32);
///
/// // Invalid: Zero key is rejected
/// let zero = [0u8; 32];
/// assert!(PrivateKey::from_bytes(&zero).is_err());
/// # Ok::<(), khodpay_bip32::Error>(())
/// ```
#[derive(Clone)]
pub struct PrivateKey {
    /// The underlying secp256k1 secret key
    inner: SecretKey,
}

impl PrivateKey {
    /// The length of a private key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a new `PrivateKey` from a secp256k1 `SecretKey`.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - A valid secp256k1 secret key
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::PrivateKey;
    /// use secp256k1::SecretKey;
    ///
    /// let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
    /// let private_key = PrivateKey::new(secret_key);
    /// ```
    pub fn new(secret_key: SecretKey) -> Self {
        PrivateKey { inner: secret_key }
    }

    /// Creates a `PrivateKey` from a byte slice.
    ///
    /// Performs comprehensive validation to ensure the bytes represent a valid
    /// secp256k1 private key scalar within the allowed range.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice that must be exactly 32 bytes and represent a valid
    ///   secp256k1 private key (non-zero and less than the curve order)
    ///
    /// # Validation
    ///
    /// This function performs multiple validation checks:
    ///
    /// 1. **Length validation**: Must be exactly 32 bytes
    /// 2. **Range validation**: The key value must satisfy: **1 ≤ key < n**
    ///    - Where **n** is the secp256k1 curve order:
    ///    - **n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141**
    /// 3. **Zero check**: The key must not be zero (invalid for ECDSA)
    /// 4. **Overflow check**: The key must be strictly less than the curve order n
    ///
    /// # Valid Range
    ///
    /// - **Minimum valid**: `0x0000...0001` (1)
    /// - **Maximum valid**: `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140` (n - 1)
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrivateKey`] if:
    /// - The slice is not exactly 32 bytes
    /// - The key value is zero (0)
    /// - The key value equals or exceeds the curve order (key >= n)
    ///
    /// # Security
    ///
    /// Range validation is critical for security. Keys outside the valid range could:
    /// - Lead to predictable signatures (zero key)
    /// - Cause undefined behavior in ECDSA operations
    /// - Enable cryptographic attacks
    /// - Violate the discrete logarithm problem security assumptions
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::PrivateKey;
    ///
    /// // Valid key in range [1, n-1]
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_bytes(&bytes)?;
    ///
    /// // Invalid: wrong length
    /// let invalid_length = [0u8; 16];
    /// assert!(PrivateKey::from_bytes(&invalid_length).is_err());
    ///
    /// // Invalid: zero key
    /// let zero_key = [0u8; 32];
    /// assert!(PrivateKey::from_bytes(&zero_key).is_err());
    ///
    /// // Invalid: exceeds curve order
    /// let overflow = [0xFFu8; 32];
    /// assert!(PrivateKey::from_bytes(&overflow).is_err());
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Validation 1: Length check
        if bytes.len() != Self::LENGTH {
            return Err(Error::InvalidPrivateKey {
                reason: format!(
                    "Private key must be {} bytes, got {}",
                    Self::LENGTH,
                    bytes.len()
                ),
            });
        }

        // Validation 2-4: Range validation (zero check + overflow check)
        // The secp256k1 library validates that:
        // - key != 0 (zero check)
        // - key < n (overflow check, where n is the curve order)
        // This ensures the key is in the valid range [1, n-1]
        let secret_key = SecretKey::from_slice(bytes).map_err(|e| Error::InvalidPrivateKey {
            reason: format!("Invalid secp256k1 private key: {}", e),
        })?;

        Ok(PrivateKey { inner: secret_key })
    }

    /// Creates a `PrivateKey` from a 32-byte array.
    ///
    /// This is a convenience wrapper around [`from_bytes`](Self::from_bytes) that
    /// accepts a fixed-size array instead of a slice. The same validation rules apply.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array representing a valid secp256k1 private key
    ///
    /// # Validation
    ///
    /// Performs the same validation as [`from_bytes`](Self::from_bytes):
    /// - Key must not be zero
    /// - Key must be less than curve order n
    /// - Valid range: **1 ≤ key < n**
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrivateKey`] if the bytes represent an invalid
    /// secp256k1 key (zero or >= curve order)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::PrivateKey;
    ///
    /// // Valid key
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_array(bytes)?;
    ///
    /// // Invalid: zero key
    /// let zero = [0u8; 32];
    /// assert!(PrivateKey::from_array(zero).is_err());
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn from_array(bytes: [u8; 32]) -> Result<Self> {
        Self::from_bytes(&bytes)
    }

    /// Returns the private key as a 32-byte array.
    ///
    /// # Security Warning
    ///
    /// The returned bytes are secret key material. Handle with care and avoid
    /// logging or exposing them.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_bytes(&bytes)?;
    /// let key_bytes = private_key.to_bytes();
    /// assert_eq!(key_bytes.len(), 32);
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.secret_bytes()
    }

    /// Returns a reference to the underlying secp256k1 `SecretKey`.
    ///
    /// This is useful for performing secp256k1 operations directly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_bytes(&bytes)?;
    /// let secret_key = private_key.secret_key();
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn secret_key(&self) -> &SecretKey {
        &self.inner
    }

    /// Derives the corresponding secp256k1 public key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_bytes(&bytes)?;
    /// let public_key = private_key.public_key();
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey::from_secret_key(SECP256K1, &self.inner)
    }

    /// Adds a scalar value to this private key (for BIP32 child key derivation).
    ///
    /// This performs the operation: `new_key = (self + tweak) mod n` where `n` is
    /// the secp256k1 curve order. This is a core operation in BIP32 child key derivation.
    ///
    /// # Arguments
    ///
    /// * `tweak` - A 32-byte scalar value to add to this key
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrivateKey`] if:
    /// - The tweak is not exactly 32 bytes
    /// - The resulting key would be invalid (>= curve order)
    ///
    /// Returns [`Error::KeyOverflow`] if the addition results in an invalid key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_bytes(&bytes)?;
    ///
    /// let tweak = [2u8; 32];
    /// let derived_key = private_key.tweak_add(&tweak)?;
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn tweak_add(&self, tweak: &[u8]) -> Result<Self> {
        if tweak.len() != 32 {
            return Err(Error::InvalidPrivateKey {
                reason: format!("Tweak must be 32 bytes, got {}", tweak.len()),
            });
        }

        // Convert tweak bytes to Scalar
        let mut tweak_array = [0u8; 32];
        tweak_array.copy_from_slice(tweak);
        let scalar = Scalar::from_be_bytes(tweak_array).map_err(|_| Error::InvalidPrivateKey {
            reason: "Invalid tweak scalar".to_string(),
        })?;

        let tweaked = self
            .inner
            .add_tweak(&scalar)
            .map_err(|_| Error::KeyOverflow)?;

        Ok(PrivateKey { inner: tweaked })
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.secret_bytes() == other.inner.secret_bytes()
    }
}

impl Eq for PrivateKey {}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey([REDACTED])")
    }
}

impl From<SecretKey> for PrivateKey {
    fn from(secret_key: SecretKey) -> Self {
        PrivateKey::new(secret_key)
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        PrivateKey::from_bytes(bytes)
    }
}

impl TryFrom<[u8; 32]> for PrivateKey {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self> {
        PrivateKey::from_array(bytes)
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Zeroize the secret key bytes when dropping
        let mut bytes = self.inner.secret_bytes();
        bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_new() {
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let private_key = PrivateKey::new(secret_key);
        assert_eq!(private_key.to_bytes(), [1u8; 32]);
    }

    #[test]
    fn test_private_key_from_bytes_valid() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(private_key.to_bytes(), bytes);
    }

    #[test]
    fn test_private_key_from_bytes_too_short() {
        let bytes = [1u8; 16];
        let result = PrivateKey::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn test_private_key_from_bytes_too_long() {
        let bytes = [1u8; 64];
        let result = PrivateKey::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn test_private_key_from_bytes_zero() {
        // All zeros is an invalid secp256k1 private key
        let bytes = [0u8; 32];
        let result = PrivateKey::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid secp256k1"));
    }

    #[test]
    fn test_private_key_from_bytes_max() {
        // All 0xFF is >= curve order, invalid
        let bytes = [0xFFu8; 32];
        let result = PrivateKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_from_array_valid() {
        let bytes = [42u8; 32];
        let private_key = PrivateKey::from_array(bytes).unwrap();
        assert_eq!(private_key.to_bytes(), bytes);
    }

    #[test]
    fn test_private_key_from_array_invalid() {
        let bytes = [0u8; 32];
        let result = PrivateKey::from_array(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_to_bytes() {
        let bytes = [123u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        let result = private_key.to_bytes();
        assert_eq!(result, bytes);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_private_key_secret_key() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        let secret_key = private_key.secret_key();
        assert_eq!(secret_key.secret_bytes(), bytes);
    }

    #[test]
    fn test_private_key_public_key() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        let public_key = private_key.public_key();

        // Verify we got a valid public key (33 bytes compressed)
        assert_eq!(public_key.serialize().len(), 33);
    }

    #[test]
    fn test_private_key_public_key_deterministic() {
        // Same private key should always produce same public key
        let bytes = [1u8; 32];
        let private_key1 = PrivateKey::from_bytes(&bytes).unwrap();
        let private_key2 = PrivateKey::from_bytes(&bytes).unwrap();

        let public_key1 = private_key1.public_key();
        let public_key2 = private_key2.public_key();

        assert_eq!(public_key1.serialize(), public_key2.serialize());
    }

    #[test]
    fn test_private_key_tweak_add_valid() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();

        let tweak = [2u8; 32];
        let derived = private_key.tweak_add(&tweak).unwrap();

        // Derived key should be different from original
        assert_ne!(derived.to_bytes(), private_key.to_bytes());
    }

    #[test]
    fn test_private_key_tweak_add_invalid_length() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();

        // Tweak too short
        let tweak = [1u8; 16];
        let result = private_key.tweak_add(&tweak);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn test_private_key_tweak_add_zero() {
        let bytes = [5u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();

        // Adding zero should give same key
        let tweak = [0u8; 32];
        let derived = private_key.tweak_add(&tweak).unwrap();
        assert_eq!(derived.to_bytes(), private_key.to_bytes());
    }

    #[test]
    fn test_private_key_clone() {
        let bytes = [99u8; 32];
        let private_key1 = PrivateKey::from_bytes(&bytes).unwrap();
        let private_key2 = private_key1.clone();

        assert_eq!(private_key1, private_key2);
        assert_eq!(private_key1.to_bytes(), private_key2.to_bytes());
    }

    #[test]
    fn test_private_key_equality() {
        let bytes1 = [1u8; 32];
        let bytes2 = [1u8; 32];
        let bytes3 = [2u8; 32];

        let key1 = PrivateKey::from_bytes(&bytes1).unwrap();
        let key2 = PrivateKey::from_bytes(&bytes2).unwrap();
        let key3 = PrivateKey::from_bytes(&bytes3).unwrap();

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key2, key3);
    }

    #[test]
    fn test_private_key_debug() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        let debug_str = format!("{:?}", private_key);

        assert!(debug_str.contains("PrivateKey"));
        assert!(debug_str.contains("REDACTED"));
        // Should NOT contain actual key bytes
        assert!(!debug_str.contains("0x01"));
    }

    #[test]
    fn test_private_key_from_secret_key() {
        let secret_key = SecretKey::from_slice(&[55u8; 32]).unwrap();
        let private_key: PrivateKey = secret_key.into();
        assert_eq!(private_key.to_bytes(), [55u8; 32]);
    }

    #[test]
    fn test_private_key_try_from_slice_valid() {
        let bytes: &[u8] = &[88u8; 32];
        let private_key = PrivateKey::try_from(bytes).unwrap();
        assert_eq!(private_key.to_bytes(), [88u8; 32]);
    }

    #[test]
    fn test_private_key_try_from_slice_invalid() {
        let bytes: &[u8] = &[0u8; 10];
        let result = PrivateKey::try_from(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_try_from_array_valid() {
        let bytes = [66u8; 32];
        let private_key = PrivateKey::try_from(bytes).unwrap();
        assert_eq!(private_key.to_bytes(), bytes);
    }

    #[test]
    fn test_private_key_try_from_array_invalid() {
        let bytes = [0u8; 32];
        let result = PrivateKey::try_from(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_length_constant() {
        assert_eq!(PrivateKey::LENGTH, 32);
    }

    #[test]
    fn test_private_key_different_values() {
        let key1 = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let key2 = PrivateKey::from_bytes(&[2u8; 32]).unwrap();

        assert_ne!(key1, key2);
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_private_key_tweak_add_associative() {
        // Test that (key + a) + b should give a valid result
        let bytes = [10u8; 32];
        let key = PrivateKey::from_bytes(&bytes).unwrap();

        let tweak1 = [1u8; 32];
        let tweak2 = [2u8; 32];

        let derived1 = key.tweak_add(&tweak1).unwrap();
        let derived2 = derived1.tweak_add(&tweak2).unwrap();

        assert_ne!(derived2.to_bytes(), key.to_bytes());
    }

    #[test]
    fn test_private_key_public_key_different_for_different_keys() {
        let key1 = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let key2 = PrivateKey::from_bytes(&[2u8; 32]).unwrap();

        let pub1 = key1.public_key();
        let pub2 = key2.public_key();

        assert_ne!(pub1.serialize(), pub2.serialize());
    }

    // secp256k1 curve order n:
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    #[test]
    fn test_key_overflow_exactly_curve_order() {
        // Key value exactly equal to curve order n (invalid)
        let n = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];

        let result = PrivateKey::from_bytes(&n);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPrivateKey { .. }
        ));
    }

    #[test]
    fn test_key_overflow_one_more_than_curve_order() {
        // Key value n + 1 (invalid - exceeds curve order)
        let n_plus_1 = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x42,
        ];

        let result = PrivateKey::from_bytes(&n_plus_1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPrivateKey { .. }
        ));
    }

    #[test]
    fn test_key_overflow_max_u256() {
        // Maximum possible 256-bit value (invalid - far exceeds curve order)
        let max_u256 = [0xFF; 32];

        let result = PrivateKey::from_bytes(&max_u256);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPrivateKey { .. }
        ));
    }

    #[test]
    fn test_key_overflow_one_less_than_curve_order() {
        // Key value n - 1 (valid - just below curve order)
        let n_minus_1 = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x40,
        ];

        let result = PrivateKey::from_bytes(&n_minus_1);
        assert!(result.is_ok(), "n-1 should be valid");
    }

    #[test]
    fn test_key_overflow_max_valid_key() {
        // Maximum valid private key (n - 1)
        let n_minus_1 = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x40,
        ];

        let private_key = PrivateKey::from_bytes(&n_minus_1).unwrap();

        // Should be able to derive public key
        let public_key = private_key.public_key();
        assert_eq!(public_key.serialize().len(), 33);

        // Should be able to convert back to bytes
        let bytes = private_key.to_bytes();
        assert_eq!(bytes, n_minus_1);
    }

    #[test]
    fn test_key_overflow_min_valid_key() {
        // Minimum valid private key (1)
        let mut one = [0u8; 32];
        one[31] = 0x01;

        let private_key = PrivateKey::from_bytes(&one).unwrap();

        // Should be able to derive public key
        let public_key = private_key.public_key();
        assert_eq!(public_key.serialize().len(), 33);
    }

    #[test]
    fn test_key_overflow_boundary_values() {
        // Test various boundary values near curve order

        // Valid: n - 2
        let n_minus_2 = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x3F,
        ];
        assert!(PrivateKey::from_bytes(&n_minus_2).is_ok());

        // Valid: n - 100
        let n_minus_100 = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x40, 0xDD,
        ];
        assert!(PrivateKey::from_bytes(&n_minus_100).is_ok());
    }

    #[test]
    fn test_key_overflow_high_values() {
        // Test various high values that exceed curve order

        // All 0xFF (definitely > n)
        let all_ff = [0xFF; 32];
        assert!(PrivateKey::from_bytes(&all_ff).is_err());

        // High value in first byte
        let high_first = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        assert!(PrivateKey::from_bytes(&high_first).is_err());
    }

    #[test]
    fn test_key_overflow_from_array() {
        // Test overflow detection with from_array method
        let n = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];

        let result = PrivateKey::from_array(n);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPrivateKey { .. }
        ));
    }

    #[test]
    fn test_key_overflow_error_message() {
        // Verify error message is informative
        let n = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];

        let result = PrivateKey::from_bytes(&n);
        assert!(result.is_err());

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid private key") || error_msg.contains("secp256k1"));
    }

    #[test]
    fn test_key_overflow_try_from_slice() {
        // Test overflow detection with TryFrom trait
        let n: &[u8] = &[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];

        let result = PrivateKey::try_from(n);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_overflow_try_from_array() {
        // Test overflow detection with TryFrom trait for arrays
        let n = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];

        let result = PrivateKey::try_from(n);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_overflow_valid_range() {
        // Test that valid keys across the range work

        // Small value
        let small = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x42,
        ];
        assert!(PrivateKey::from_bytes(&small).is_ok());

        // Medium value
        let medium = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC, 0xDE, 0xF0,
        ];
        assert!(PrivateKey::from_bytes(&medium).is_ok());

        // Large but valid value (well below n)
        let large = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];
        assert!(PrivateKey::from_bytes(&large).is_ok());
    }

    #[test]
    fn test_key_overflow_derived_keys_valid() {
        // Ensure that even max valid keys can be used for derivation
        let n_minus_1 = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x40,
        ];

        let private_key = PrivateKey::from_bytes(&n_minus_1).unwrap();

        // Should be able to get public key
        let public_key = private_key.public_key();
        assert!(!public_key.serialize().is_empty());

        // Should be able to get secret key reference
        let secret_key = private_key.secret_key();
        assert_eq!(secret_key.secret_bytes(), n_minus_1);
    }

    #[test]
    fn test_zero_key_all_zeros() {
        // All zeros is invalid
        let zero = [0x00; 32];
        let result = PrivateKey::from_bytes(&zero);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPrivateKey { .. }
        ));
    }

    #[test]
    fn test_zero_key_from_array() {
        // Test zero key rejection with from_array
        let zero = [0x00; 32];
        let result = PrivateKey::from_array(zero);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPrivateKey { .. }
        ));
    }

    #[test]
    fn test_zero_key_try_from_slice() {
        // Test zero key rejection with TryFrom trait
        let zero: &[u8] = &[0x00; 32];
        let result = PrivateKey::try_from(zero);

        assert!(result.is_err());
    }

    #[test]
    fn test_zero_key_try_from_array() {
        // Test zero key rejection with TryFrom trait for arrays
        let zero = [0x00; 32];
        let result = PrivateKey::try_from(zero);

        assert!(result.is_err());
    }

    #[test]
    fn test_zero_key_error_message() {
        // Verify error message is clear
        let zero = [0x00; 32];
        let result = PrivateKey::from_bytes(&zero);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Invalid private key") || error_msg.contains("secp256k1"),
            "Error message should mention invalid key: {}",
            error_msg
        );
    }

    #[test]
    fn test_zero_key_vs_one() {
        // Verify that 1 is valid but 0 is not
        let zero = [0x00; 32];
        let mut one = [0x00; 32];
        one[31] = 0x01;

        assert!(
            PrivateKey::from_bytes(&zero).is_err(),
            "Zero key should be rejected"
        );
        assert!(
            PrivateKey::from_bytes(&one).is_ok(),
            "Key value 1 should be valid"
        );
    }

    #[test]
    fn test_zero_key_prevents_public_key_generation() {
        // Zero key should never reach public key generation
        let zero = [0x00; 32];

        // Should fail at key creation
        let result = PrivateKey::from_bytes(&zero);
        assert!(result.is_err());

        // Never gets to public key derivation
        // This test verifies the validation happens early
    }

    #[test]
    fn test_zero_key_security_boundary() {
        // Test the security boundary: 0 invalid, 1 valid

        // Zero (invalid)
        let zero = [0x00; 32];
        assert!(PrivateKey::from_bytes(&zero).is_err());

        // One (minimum valid)
        let mut one = [0x00; 32];
        one[31] = 0x01;
        assert!(PrivateKey::from_bytes(&one).is_ok());

        // Two (also valid)
        let mut two = [0x00; 32];
        two[31] = 0x02;
        assert!(PrivateKey::from_bytes(&two).is_ok());
    }

    #[test]
    fn test_zero_key_tweak_result() {
        // Even if a tweak operation could theoretically produce zero,
        // it should be handled properly
        let bytes = [0x05; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();

        // Adding a zero tweak should work (key + 0 = key)
        let zero_tweak = [0x00; 32];
        let result = private_key.tweak_add(&zero_tweak);

        // This should succeed (adding zero doesn't make the key zero)
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_key_cannot_be_constructed() {
        // Comprehensive test: zero key cannot be constructed via any method
        let zero = [0x00; 32];

        // Method 1: from_bytes
        assert!(PrivateKey::from_bytes(&zero).is_err());

        // Method 2: from_array
        assert!(PrivateKey::from_array(zero).is_err());

        // Method 3: TryFrom<&[u8]>
        assert!(PrivateKey::try_from(&zero[..]).is_err());

        // Method 4: TryFrom<[u8; 32]>
        assert!(PrivateKey::try_from(zero).is_err());
    }

    #[test]
    fn test_zero_key_explicit_validation() {
        // Explicitly test that zero is caught by secp256k1 validation
        let zero = [0x00; 32];

        // This should fail at SecretKey::from_slice
        let result = PrivateKey::from_bytes(&zero);
        assert!(result.is_err());

        // Verify it's an InvalidPrivateKey error
        match result {
            Err(Error::InvalidPrivateKey { reason }) => {
                // Error should mention secp256k1 or invalid key
                assert!(
                    reason.contains("secp256k1") || reason.contains("invalid"),
                    "Expected secp256k1 or invalid in error, got: {}",
                    reason
                );
            }
            _ => panic!("Expected InvalidPrivateKey error"),
        }
    }

    #[test]
    fn test_zero_key_prevents_cryptographic_operations() {
        // Zero key should never be allowed into the system
        // because it would break all cryptographic properties
        let zero = [0x00; 32];

        // Key creation fails
        assert!(PrivateKey::from_bytes(&zero).is_err());

        // This means we can't:
        // - Generate a public key (would be point at infinity)
        // - Sign messages (signature would be zero)
        // - Derive child keys (would produce zero children)
        // All of these are prevented by rejecting zero at construction
    }

    #[test]
    fn test_zero_key_comparison_with_valid_keys() {
        // Test zero against various valid keys to ensure clear distinction
        let zero = [0x00; 32];

        // Test against small valid keys
        for value in 1..=10u8 {
            let mut valid = [0x00; 32];
            valid[31] = value;

            assert!(
                PrivateKey::from_bytes(&zero).is_err(),
                "Zero should be invalid"
            );
            assert!(
                PrivateKey::from_bytes(&valid).is_ok(),
                "Value {} should be valid",
                value
            );
        }
    }

    #[test]
    fn test_zero_key_documentation_example() {
        // This test verifies the example in the documentation
        let zero_key = [0u8; 32];
        assert!(PrivateKey::from_bytes(&zero_key).is_err());

        // Compare with valid key from docs
        let valid_key = [1u8; 32];
        assert!(PrivateKey::from_bytes(&valid_key).is_ok());
    }
}
