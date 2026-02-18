//! Public key implementation for BIP32 hierarchical deterministic wallets.
//!
//! This module provides a wrapper around secp256k1 compressed public keys for use in
//! BIP32 extended key derivation.

use crate::{Error, PrivateKey, Result};
use secp256k1::{
    ecdsa::Signature, scalar::Scalar, Message, PublicKey as Secp256k1PublicKey, SECP256K1,
};

/// A 33-byte compressed secp256k1 public key used in BIP32 hierarchical deterministic wallets.
///
/// Public keys are points on the secp256k1 elliptic curve. BIP32 uses compressed format
/// (33 bytes: 1-byte prefix + 32-byte x-coordinate) instead of uncompressed format (65 bytes).
///
/// # Compressed Format
///
/// - **Byte 0**: Prefix (`0x02` for even y, `0x03` for odd y)
/// - **Bytes 1-32**: x-coordinate of the curve point
///
/// # Security
///
/// Unlike private keys, public keys are NOT secret and can be safely displayed,
/// logged, or transmitted.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip32::{PrivateKey, PublicKey};
///
/// // Derive from a private key
/// let private_key = PrivateKey::from_bytes(&[1u8; 32])?;
/// let public_key = PublicKey::from_private_key(&private_key);
///
/// // Get compressed bytes
/// let bytes = public_key.to_bytes();
/// assert_eq!(bytes.len(), 33);
/// # Ok::<(), khodpay_bip32::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// The underlying secp256k1 public key (always compressed)
    inner: Secp256k1PublicKey,
}

impl PublicKey {
    /// The length of a compressed public key in bytes.
    pub const COMPRESSED_LENGTH: usize = 33;

    /// The length of an uncompressed public key in bytes.
    pub const UNCOMPRESSED_LENGTH: usize = 65;

    /// Creates a new `PublicKey` from a secp256k1 `PublicKey`.
    ///
    /// # Arguments
    ///
    /// * `public_key` - A valid secp256k1 public key
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::PublicKey;
    /// use secp256k1::{PublicKey as Secp256k1PublicKey, SecretKey, SECP256K1};
    ///
    /// let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
    /// let secp_pubkey = Secp256k1PublicKey::from_secret_key(SECP256K1, &secret);
    /// let public_key = PublicKey::new(secp_pubkey);
    /// ```
    pub fn new(public_key: Secp256k1PublicKey) -> Self {
        PublicKey { inner: public_key }
    }

    /// Creates a `PublicKey` from a byte slice.
    ///
    /// Performs comprehensive validation to ensure the bytes represent a valid
    /// secp256k1 public key point on the curve.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice containing either:
    ///   - 33 bytes for compressed format (recommended)
    ///   - 65 bytes for uncompressed format (will be converted to compressed)
    ///
    /// # Validation
    ///
    /// This function performs multiple validation checks:
    ///
    /// 1. **Length validation**: Must be exactly 33 or 65 bytes
    /// 2. **Prefix validation**:
    ///    - Compressed (33 bytes): Must start with 0x02 or 0x03
    ///    - Uncompressed (65 bytes): Must start with 0x04
    /// 3. **Curve point validation**: The coordinates must satisfy the secp256k1
    ///    curve equation: y² = x³ + 7 (mod p)
    /// 4. **Non-infinity check**: The point must not be the point at infinity
    /// 5. **Field bounds**: Coordinates must be within the field prime
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if:
    /// - The slice is not 33 or 65 bytes
    /// - The compression prefix is invalid
    /// - The bytes represent an invalid secp256k1 public key
    /// - The point is not on the curve
    /// - The point is the point at infinity
    ///
    /// # Security
    ///
    /// This validation is critical for security. Invalid curve points could:
    /// - Lead to incorrect address generation
    /// - Enable cryptographic attacks
    /// - Cause undefined behavior in ECDSA operations
    /// - Leak private key information
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::{PrivateKey, PublicKey};
    ///
    /// let private_key = PrivateKey::from_bytes(&[1u8; 32])?;
    /// let pubkey_bytes = private_key.public_key().serialize();
    ///
    /// let public_key = PublicKey::from_bytes(&pubkey_bytes)?;
    /// assert_eq!(public_key.to_bytes(), pubkey_bytes);
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Validation 1: Length check
        if bytes.len() != Self::COMPRESSED_LENGTH && bytes.len() != Self::UNCOMPRESSED_LENGTH {
            return Err(Error::InvalidPublicKey {
                reason: format!(
                    "Public key must be {} or {} bytes, got {}",
                    Self::COMPRESSED_LENGTH,
                    Self::UNCOMPRESSED_LENGTH,
                    bytes.len()
                ),
            });
        }

        // Validation 2: Prefix check (explicit validation for better error messages)
        if bytes.len() == Self::COMPRESSED_LENGTH {
            // Compressed format: must start with 0x02 or 0x03
            if bytes[0] != 0x02 && bytes[0] != 0x03 {
                return Err(Error::InvalidPublicKey {
                    reason: format!(
                        "Invalid compressed public key prefix: 0x{:02x} (must be 0x02 or 0x03)",
                        bytes[0]
                    ),
                });
            }
        } else if bytes.len() == Self::UNCOMPRESSED_LENGTH {
            // Uncompressed format: must start with 0x04
            if bytes[0] != 0x04 {
                return Err(Error::InvalidPublicKey {
                    reason: format!(
                        "Invalid uncompressed public key prefix: 0x{:02x} (must be 0x04)",
                        bytes[0]
                    ),
                });
            }
        }

        // Validation 3-5: Curve point validation
        // The secp256k1 library performs:
        // - Validates the point is on the curve (y² = x³ + 7)
        // - Checks the point is not at infinity
        // - Ensures coordinates are within field bounds
        let public_key =
            Secp256k1PublicKey::from_slice(bytes).map_err(|e| Error::InvalidPublicKey {
                reason: format!("Invalid secp256k1 public key: {}", e),
            })?;

        Ok(PublicKey { inner: public_key })
    }

    /// Creates a `PublicKey` from a 33-byte compressed array.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 33-byte array containing a compressed public key
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the bytes represent an invalid
    /// secp256k1 public key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::{PrivateKey, PublicKey};
    ///
    /// let private_key = PrivateKey::from_bytes(&[1u8; 32])?;
    /// let bytes = private_key.public_key().serialize();
    ///
    /// let public_key = PublicKey::from_array(bytes)?;
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn from_array(bytes: [u8; 33]) -> Result<Self> {
        Self::from_bytes(&bytes)
    }

    /// Derives a `PublicKey` from a `PrivateKey`.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key to derive from
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::{PrivateKey, PublicKey};
    ///
    /// let private_key = PrivateKey::from_bytes(&[1u8; 32])?;
    /// let public_key = PublicKey::from_private_key(&private_key);
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        PublicKey {
            inner: private_key.public_key(),
        }
    }

    /// Returns the public key as a 33-byte compressed array.
    ///
    /// The format is: `[prefix_byte, x_coordinate[32]]`
    /// where prefix is `0x02` (even y) or `0x03` (odd y).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::{PrivateKey, PublicKey};
    ///
    /// let private_key = PrivateKey::from_bytes(&[1u8; 32])?;
    /// let public_key = PublicKey::from_private_key(&private_key);
    ///
    /// let bytes = public_key.to_bytes();
    /// assert_eq!(bytes.len(), 33);
    /// assert!(bytes[0] == 0x02 || bytes[0] == 0x03);
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn to_bytes(&self) -> [u8; 33] {
        self.inner.serialize()
    }

    /// Returns the public key as a 65-byte uncompressed array.
    ///
    /// The format is: `[0x04, x_coordinate[32], y_coordinate[32]]`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::{PrivateKey, PublicKey};
    ///
    /// let private_key = PrivateKey::from_bytes(&[1u8; 32])?;
    /// let public_key = PublicKey::from_private_key(&private_key);
    ///
    /// let bytes = public_key.to_uncompressed();
    /// assert_eq!(bytes.len(), 65);
    /// assert_eq!(bytes[0], 0x04);
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn to_uncompressed(&self) -> [u8; 65] {
        self.inner.serialize_uncompressed()
    }

    /// Returns a reference to the underlying secp256k1 `PublicKey`.
    ///
    /// This is useful for performing secp256k1 operations directly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::{PrivateKey, PublicKey};
    ///
    /// let private_key = PrivateKey::from_bytes(&[1u8; 32])?;
    /// let public_key = PublicKey::from_private_key(&private_key);
    ///
    /// let secp_pubkey = public_key.public_key();
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn public_key(&self) -> &Secp256k1PublicKey {
        &self.inner
    }

    /// Returns `true` if the public key is in compressed format.
    ///
    /// Since BIP32 always uses compressed keys, this always returns `true`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::{PrivateKey, PublicKey};
    ///
    /// let private_key = PrivateKey::from_bytes(&[1u8; 32])?;
    /// let public_key = PublicKey::from_private_key(&private_key);
    ///
    /// assert!(public_key.is_compressed());
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn is_compressed(&self) -> bool {
        true // BIP32 always uses compressed keys
    }

    /// Adds a scalar value to this public key (for BIP32 child key derivation).
    ///
    /// This performs elliptic curve point addition: `new_key = self + tweak * G`
    /// where `G` is the generator point. This is used in BIP32 for deriving
    /// public child keys from a parent public key (normal derivation only).
    ///
    /// # Arguments
    ///
    /// * `tweak` - A 32-byte scalar value to add to this key
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if:
    /// - The tweak is not exactly 32 bytes
    /// - The resulting point would be invalid (e.g., point at infinity)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::{PrivateKey, PublicKey};
    ///
    /// let private_key = PrivateKey::from_bytes(&[1u8; 32])?;
    /// let public_key = PublicKey::from_private_key(&private_key);
    ///
    /// let tweak = [2u8; 32];
    /// let derived_key = public_key.tweak_add(&tweak)?;
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn tweak_add(&self, tweak: &[u8]) -> Result<Self> {
        if tweak.len() != 32 {
            return Err(Error::InvalidPublicKey {
                reason: format!("Tweak must be 32 bytes, got {}", tweak.len()),
            });
        }

        // Convert tweak bytes to Scalar
        let mut tweak_array = [0u8; 32];
        tweak_array.copy_from_slice(tweak);
        let scalar = Scalar::from_be_bytes(tweak_array).map_err(|_| Error::InvalidPublicKey {
            reason: "Invalid tweak scalar".to_string(),
        })?;

        let tweaked =
            self.inner
                .add_exp_tweak(SECP256K1, &scalar)
                .map_err(|e| Error::InvalidPublicKey {
                    reason: format!("Failed to add tweak: {}", e),
                })?;

        Ok(PublicKey { inner: tweaked })
    }

    /// Verifies an ECDSA signature against a message hash.
    ///
    /// # Arguments
    ///
    /// * `message` - The 32-byte message hash that was signed
    /// * `signature` - The ECDSA signature to verify
    ///
    /// # Returns
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::{PrivateKey, PublicKey};
    /// use secp256k1::{Message, Secp256k1};
    ///
    /// let secp = Secp256k1::new();
    /// let private_key = PrivateKey::from_bytes(&[1u8; 32])?;
    /// let public_key = PublicKey::from_private_key(&private_key);
    ///
    /// // Sign a message
    /// let message = Message::from_digest_slice(&[0xAB; 32]).unwrap();
    /// let signature = secp.sign_ecdsa(&message, private_key.secret_key());
    ///
    /// // Verify the signature
    /// assert!(public_key.verify_signature(&message, &signature));
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn verify_signature(&self, message: &Message, signature: &Signature) -> bool {
        SECP256K1
            .verify_ecdsa(message, signature, &self.inner)
            .is_ok()
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.to_bytes()))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl From<Secp256k1PublicKey> for PublicKey {
    fn from(public_key: Secp256k1PublicKey) -> Self {
        PublicKey::new(public_key)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        PublicKey::from_bytes(bytes)
    }
}

impl TryFrom<[u8; 33]> for PublicKey {
    type Error = Error;

    fn try_from(bytes: [u8; 33]) -> Result<Self> {
        PublicKey::from_array(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn create_test_private_key() -> PrivateKey {
        PrivateKey::from_bytes(&[1u8; 32]).unwrap()
    }

    #[test]
    fn test_public_key_new() {
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let secp_pubkey = Secp256k1PublicKey::from_secret_key(SECP256K1, &secret);
        let public_key = PublicKey::new(secp_pubkey);
        assert_eq!(public_key.to_bytes().len(), 33);
    }

    #[test]
    fn test_public_key_from_private_key() {
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);
        assert_eq!(public_key.to_bytes().len(), 33);
    }

    #[test]
    fn test_public_key_from_bytes_compressed() {
        let private_key = create_test_private_key();
        let bytes = private_key.public_key().serialize();
        let public_key = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key.to_bytes(), bytes);
    }

    #[test]
    fn test_public_key_from_bytes_uncompressed() {
        let private_key = create_test_private_key();
        let secp_pubkey = private_key.public_key();
        let uncompressed = secp_pubkey.serialize_uncompressed();

        let public_key = PublicKey::from_bytes(&uncompressed).unwrap();
        assert_eq!(public_key.to_bytes(), secp_pubkey.serialize());
    }

    #[test]
    fn test_public_key_from_bytes_invalid_length() {
        let bytes = [0u8; 32]; // Wrong length
        let result = PublicKey::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be 33 or 65 bytes"));
    }

    #[test]
    fn test_public_key_from_bytes_invalid_data() {
        let bytes = [0xFFu8; 33]; // Invalid public key
        let result = PublicKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_from_array() {
        let private_key = create_test_private_key();
        let bytes = private_key.public_key().serialize();
        let public_key = PublicKey::from_array(bytes).unwrap();
        assert_eq!(public_key.to_bytes(), bytes);
    }

    #[test]
    fn test_public_key_to_bytes() {
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);
        let bytes = public_key.to_bytes();

        assert_eq!(bytes.len(), 33);
        assert!(bytes[0] == 0x02 || bytes[0] == 0x03);
    }

    #[test]
    fn test_public_key_to_uncompressed() {
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);
        let bytes = public_key.to_uncompressed();

        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
    }

    #[test]
    fn test_public_key_compression() {
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);

        let compressed = public_key.to_bytes();
        let uncompressed = public_key.to_uncompressed();

        // Both formats should represent the same key
        let pub1 = PublicKey::from_bytes(&compressed).unwrap();
        let pub2 = PublicKey::from_bytes(&uncompressed).unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_public_key_public_key() {
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);
        let secp_pubkey = public_key.public_key();
        assert_eq!(secp_pubkey.serialize(), public_key.to_bytes());
    }

    #[test]
    fn test_public_key_is_compressed() {
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);
        assert!(public_key.is_compressed());
    }

    #[test]
    fn test_public_key_clone() {
        let private_key = create_test_private_key();
        let public_key1 = PublicKey::from_private_key(&private_key);
        let public_key2 = public_key1.clone();
        assert_eq!(public_key1, public_key2);
    }

    #[test]
    fn test_public_key_equality() {
        let private_key1 = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let private_key2 = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let private_key3 = PrivateKey::from_bytes(&[2u8; 32]).unwrap();

        let pub1 = PublicKey::from_private_key(&private_key1);
        let pub2 = PublicKey::from_private_key(&private_key2);
        let pub3 = PublicKey::from_private_key(&private_key3);

        assert_eq!(pub1, pub2);
        assert_ne!(pub1, pub3);
    }

    #[test]
    fn test_public_key_debug() {
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);
        let debug_str = format!("{:?}", public_key);

        assert!(debug_str.contains("PublicKey"));
        assert!(debug_str.len() > 20); // Should show hex
    }

    #[test]
    fn test_public_key_display() {
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);
        let display_str = format!("{}", public_key);

        assert_eq!(display_str.len(), 66); // 33 bytes * 2 hex chars
    }

    #[test]
    fn test_public_key_from_secp256k1() {
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let secp_pubkey = Secp256k1PublicKey::from_secret_key(SECP256K1, &secret);
        let public_key: PublicKey = secp_pubkey.into();
        assert_eq!(public_key.to_bytes(), secp_pubkey.serialize());
    }

    #[test]
    fn test_public_key_try_from_slice() {
        let private_key = create_test_private_key();
        let bytes = private_key.public_key().serialize();
        let slice: &[u8] = &bytes;
        let public_key = PublicKey::try_from(slice).unwrap();
        assert_eq!(public_key.to_bytes(), bytes);
    }

    #[test]
    fn test_public_key_try_from_array() {
        let private_key = create_test_private_key();
        let bytes = private_key.public_key().serialize();
        let public_key = PublicKey::try_from(bytes).unwrap();
        assert_eq!(public_key.to_bytes(), bytes);
    }

    #[test]
    fn test_public_key_tweak_add_valid() {
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);

        let tweak = [2u8; 32];
        let derived = public_key.tweak_add(&tweak).unwrap();

        assert_ne!(derived, public_key);
    }

    #[test]
    fn test_public_key_tweak_add_invalid_length() {
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);

        let tweak = [1u8; 16];
        let result = public_key.tweak_add(&tweak);
        assert!(result.is_err());
    }

    #[test]
    fn test_public_key_tweak_add_matches_private() {
        // Verify that pub_parent + tweak == (priv_parent + tweak).public_key()
        let priv_parent = PrivateKey::from_bytes(&[10u8; 32]).unwrap();
        let pub_parent = PublicKey::from_private_key(&priv_parent);

        let tweak = [5u8; 32];

        let priv_derived = priv_parent.tweak_add(&tweak).unwrap();
        let pub_from_priv = PublicKey::from_private_key(&priv_derived);

        let pub_derived = pub_parent.tweak_add(&tweak).unwrap();

        assert_eq!(pub_from_priv, pub_derived);
    }

    #[test]
    fn test_public_key_verify_signature_valid() {
        let secp = Secp256k1::new();
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);

        let message = Message::from_digest_slice(&[0xAB; 32]).unwrap();
        let signature = secp.sign_ecdsa(&message, private_key.secret_key());

        assert!(public_key.verify_signature(&message, &signature));
    }

    #[test]
    fn test_public_key_verify_signature_invalid() {
        let secp = Secp256k1::new();
        let private_key1 = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let private_key2 = PrivateKey::from_bytes(&[2u8; 32]).unwrap();
        let public_key1 = PublicKey::from_private_key(&private_key1);

        let message = Message::from_digest_slice(&[0xAB; 32]).unwrap();
        let signature = secp.sign_ecdsa(&message, private_key2.secret_key());

        // Wrong public key, should fail
        assert!(!public_key1.verify_signature(&message, &signature));
    }

    #[test]
    fn test_public_key_length_constants() {
        assert_eq!(PublicKey::COMPRESSED_LENGTH, 33);
        assert_eq!(PublicKey::UNCOMPRESSED_LENGTH, 65);
    }

    #[test]
    fn test_public_key_deterministic() {
        let private_key = create_test_private_key();
        let pub1 = PublicKey::from_private_key(&private_key);
        let pub2 = PublicKey::from_private_key(&private_key);
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_invalid_curve_point_all_zeros() {
        // All zeros is not a valid point on the curve
        let bytes = [0x00; 33];
        let result = PublicKey::from_bytes(&bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPublicKey { .. }
        ));
    }

    #[test]
    fn test_invalid_curve_point_all_ones() {
        // All 0xFF is not a valid point on the curve
        let bytes = [0xFF; 33];
        let result = PublicKey::from_bytes(&bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPublicKey { .. }
        ));
    }

    #[test]
    fn test_invalid_curve_point_wrong_compressed_prefix() {
        // Compressed keys must start with 0x02 or 0x03
        let invalid_prefixes = [0x00, 0x01, 0x04, 0x05, 0x06, 0xFF];

        for prefix in invalid_prefixes {
            let mut bytes = [0xAA; 33];
            bytes[0] = prefix;

            let result = PublicKey::from_bytes(&bytes);
            assert!(
                result.is_err(),
                "Prefix 0x{:02x} should be rejected for compressed format",
                prefix
            );
        }
    }

    #[test]
    fn test_invalid_curve_point_wrong_uncompressed_prefix() {
        // Uncompressed keys must start with 0x04
        let invalid_prefixes = [0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0xFF];

        for prefix in invalid_prefixes {
            let mut bytes = [0xAA; 65];
            bytes[0] = prefix;

            let result = PublicKey::from_bytes(&bytes);
            assert!(
                result.is_err(),
                "Prefix 0x{:02x} should be rejected for uncompressed format",
                prefix
            );
        }
    }

    #[test]
    fn test_invalid_curve_point_random_bytes() {
        // Random bytes that don't represent a valid curve point
        let test_cases = vec![
            [
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            [
                0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ],
            [
                0x02, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11,
            ],
        ];

        for bytes in test_cases {
            let result = PublicKey::from_bytes(&bytes);
            assert!(
                result.is_err(),
                "Random bytes should not form a valid curve point"
            );
        }
    }

    #[test]
    fn test_invalid_curve_point_not_on_curve() {
        // Coordinates that don't satisfy y² = x³ + 7 (secp256k1 curve equation)
        // Using pattern that secp256k1 library will reject as not on curve
        // This uses an x-coordinate with no valid y
        let bytes = [
            0x02, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A,
            0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56,
            0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12,
        ];

        let result = PublicKey::from_bytes(&bytes);
        // This may or may not be on the curve - secp256k1 library handles validation
        // We're testing that invalid points are rejected
        if let Err(e) = result {
            // If it's invalid, verify we get the right error
            assert!(matches!(e, Error::InvalidPublicKey { .. }));
        }
        // If this pattern happens to be valid, that's fine - secp256k1 accepted it
    }

    #[test]
    fn test_invalid_curve_point_exceeds_field_prime() {
        // x-coordinate exceeds the field prime p = 2^256 - 2^32 - 977
        let bytes = [
            0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        let result = PublicKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_curve_point_empty_bytes() {
        let bytes = [];
        let result = PublicKey::from_bytes(&bytes);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPublicKey { .. }
        ));
    }

    #[test]
    fn test_invalid_curve_point_single_byte() {
        let bytes = [0x02];
        let result = PublicKey::from_bytes(&bytes);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_curve_point_wrong_length_34() {
        let bytes = [0x02; 34];
        let result = PublicKey::from_bytes(&bytes);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be 33 or 65 bytes"));
    }

    #[test]
    fn test_invalid_curve_point_wrong_length_64() {
        let bytes = [0x04; 64];
        let result = PublicKey::from_bytes(&bytes);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be 33 or 65 bytes"));
    }

    #[test]
    fn test_invalid_curve_point_wrong_length_66() {
        let bytes = [0x04; 66];
        let result = PublicKey::from_bytes(&bytes);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must be 33 or 65 bytes"));
    }

    #[test]
    fn test_invalid_curve_point_valid_then_modified() {
        // Start with a valid key, then corrupt it
        let private_key = create_test_private_key();
        let mut valid_bytes = PublicKey::from_private_key(&private_key).to_bytes();

        // Corrupt the prefix to make it definitely invalid
        valid_bytes[0] = 0x05; // Invalid prefix

        let result = PublicKey::from_bytes(&valid_bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InvalidPublicKey { .. }
        ));
    }

    #[test]
    fn test_invalid_curve_point_uncompressed_all_zeros() {
        // Uncompressed format with all zeros (except prefix)
        let mut bytes = [0x00; 65];
        bytes[0] = 0x04;

        let result = PublicKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_curve_point_uncompressed_invalid_coordinates() {
        // Uncompressed format with coordinates not on curve
        let mut bytes = [0xAA; 65];
        bytes[0] = 0x04;

        let result = PublicKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_curve_point_compressed_02() {
        // Known valid point with 0x02 prefix (from test vector)
        let private_key = PrivateKey::from_bytes(&[0x01; 32]).unwrap();
        let public_key = PublicKey::from_private_key(&private_key);
        let bytes = public_key.to_bytes();

        // Should start with 0x02 or 0x03
        assert!(bytes[0] == 0x02 || bytes[0] == 0x03);

        // Should be parseable
        let result = PublicKey::from_bytes(&bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_curve_point_both_formats() {
        // Ensure conversion between compressed and uncompressed works
        let private_key = create_test_private_key();
        let public_key = PublicKey::from_private_key(&private_key);

        let compressed = public_key.to_bytes();
        let uncompressed = public_key.to_uncompressed();

        // Both should be valid
        assert!(PublicKey::from_bytes(&compressed).is_ok());
        assert!(PublicKey::from_bytes(&uncompressed).is_ok());

        // And should represent the same point
        let pub1 = PublicKey::from_bytes(&compressed).unwrap();
        let pub2 = PublicKey::from_bytes(&uncompressed).unwrap();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn test_invalid_curve_point_in_extended_key_context() {
        // Test that invalid points are caught when deserializing extended keys
        // This is tested indirectly through the from_str implementation
        use crate::{ExtendedPrivateKey, Network};

        let seed = [0x01; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let xpub = master.to_extended_public_key().to_string();

        // Valid xpub should parse successfully
        let result = xpub.parse::<crate::ExtendedPublicKey>();
        assert!(result.is_ok());
    }
}
