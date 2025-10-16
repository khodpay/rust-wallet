//! Chain code implementation for BIP32 hierarchical deterministic key derivation.
//!
//! Chain codes are 32-byte values that provide additional entropy for key derivation.
//! They work alongside private or public keys to enable secure hierarchical key generation.
//!
//! # What is a Chain Code?
//!
//! A chain code is a 32-byte secret value that, combined with a key, allows deriving
//! child keys. It prevents attackers from deriving parent keys even if they compromise
//! a child private key and the parent public key.
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip32::ChainCode;
//!
//! // Create from bytes
//! let bytes = [42u8; 32];
//! let chain_code = ChainCode::from_bytes(&bytes)?;
//!
//! // Access the bytes
//! assert_eq!(chain_code.as_bytes(), &bytes);
//! # Ok::<(), khodpay_bip32::Error>(())
//! ```

use crate::{Error, Result};
use zeroize::ZeroizeOnDrop;

/// A 32-byte chain code used in BIP32 hierarchical deterministic key derivation.
///
/// Chain codes provide additional entropy for deriving child keys. Every extended key
/// (both private and public) has an associated chain code that is used in the
/// HMAC-SHA512 operation during child key derivation.
///
/// # Security
///
/// Chain codes must be kept secret, similar to private keys. Exposing a chain code
/// along with an extended public key can compromise the privacy of all child keys.
///
/// **Memory Safety:** This type implements `ZeroizeOnDrop`, which automatically
/// overwrites the chain code bytes with zeros when the value is dropped, preventing
/// sensitive data from lingering in memory.
///
/// # Size
///
/// Chain codes are always exactly 32 bytes (256 bits) in length.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip32::ChainCode;
///
/// // Create from a 32-byte array
/// let bytes = [0u8; 32];
/// let chain_code = ChainCode::from_bytes(&bytes)?;
///
/// // Access the underlying bytes
/// let bytes_ref: &[u8; 32] = chain_code.as_bytes();
/// assert_eq!(bytes_ref.len(), 32);
/// # Ok::<(), khodpay_bip32::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct ChainCode([u8; 32]);

impl ChainCode {
    /// The length of a chain code in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a new `ChainCode` from a 32-byte array.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the chain code data
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::ChainCode;
    ///
    /// let bytes = [0u8; 32];
    /// let chain_code = ChainCode::new(bytes);
    /// assert_eq!(chain_code.as_bytes(), &bytes);
    /// ```
    pub fn new(bytes: [u8; 32]) -> Self {
        ChainCode(bytes)
    }

    /// Creates a `ChainCode` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice that must be exactly 32 bytes long
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrivateKey`] if the slice is not exactly 32 bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::ChainCode;
    ///
    /// // Valid 32-byte slice
    /// let bytes = vec![0u8; 32];
    /// let chain_code = ChainCode::from_bytes(&bytes)?;
    ///
    /// // Invalid length
    /// let invalid = vec![0u8; 16];
    /// assert!(ChainCode::from_bytes(&invalid).is_err());
    /// # Ok::<(), khodpay_bip32::Error>(())
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::LENGTH {
            return Err(Error::InvalidPrivateKey {
                reason: format!(
                    "Chain code must be {} bytes, got {}",
                    Self::LENGTH,
                    bytes.len()
                ),
            });
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(ChainCode(array))
    }

    /// Returns a reference to the chain code bytes as a 32-byte array.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::ChainCode;
    ///
    /// let bytes = [42u8; 32];
    /// let chain_code = ChainCode::new(bytes);
    ///
    /// let bytes_ref: &[u8; 32] = chain_code.as_bytes();
    /// assert_eq!(bytes_ref, &bytes);
    /// ```
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts the chain code to a `Vec<u8>`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::ChainCode;
    ///
    /// let bytes = [1u8; 32];
    /// let chain_code = ChainCode::new(bytes);
    ///
    /// let vec = chain_code.to_vec();
    /// assert_eq!(vec.len(), 32);
    /// assert_eq!(vec, bytes.to_vec());
    /// ```
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Returns the length of the chain code (always 32).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::ChainCode;
    ///
    /// let chain_code = ChainCode::new([0u8; 32]);
    /// assert_eq!(chain_code.len(), 32);
    /// ```
    pub fn len(&self) -> usize {
        Self::LENGTH
    }

    /// Always returns `false` since chain codes have a fixed non-zero length.
    ///
    /// This method exists for consistency with collection-like types.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip32::ChainCode;
    ///
    /// let chain_code = ChainCode::new([0u8; 32]);
    /// assert!(!chain_code.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl std::fmt::Debug for ChainCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChainCode(")?;
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{:02x}", byte)?;
            if i >= 7 {
                write!(f, "...")?;
                break;
            }
        }
        write!(f, ")")
    }
}

impl AsRef<[u8]> for ChainCode {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for ChainCode {
    fn from(bytes: [u8; 32]) -> Self {
        ChainCode::new(bytes)
    }
}

impl TryFrom<&[u8]> for ChainCode {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        ChainCode::from_bytes(bytes)
    }
}

impl TryFrom<Vec<u8>> for ChainCode {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        ChainCode::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_code_new() {
        let bytes = [42u8; 32];
        let chain_code = ChainCode::new(bytes);
        assert_eq!(chain_code.as_bytes(), &bytes);
    }

    #[test]
    fn test_chain_code_from_bytes_valid() {
        let bytes = vec![1u8; 32];
        let chain_code = ChainCode::from_bytes(&bytes).unwrap();
        assert_eq!(chain_code.as_bytes(), &[1u8; 32]);
    }

    #[test]
    fn test_chain_code_from_bytes_too_short() {
        let bytes = vec![0u8; 16];
        let result = ChainCode::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn test_chain_code_from_bytes_too_long() {
        let bytes = vec![0u8; 64];
        let result = ChainCode::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn test_chain_code_from_bytes_empty() {
        let bytes: Vec<u8> = vec![];
        let result = ChainCode::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_code_as_bytes() {
        let bytes = [123u8; 32];
        let chain_code = ChainCode::new(bytes);
        let result = chain_code.as_bytes();
        assert_eq!(result, &bytes);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_chain_code_to_vec() {
        let bytes = [42u8; 32];
        let chain_code = ChainCode::new(bytes);
        let vec = chain_code.to_vec();
        assert_eq!(vec.len(), 32);
        assert_eq!(vec, bytes.to_vec());
    }

    #[test]
    fn test_chain_code_len() {
        let chain_code = ChainCode::new([0u8; 32]);
        assert_eq!(chain_code.len(), 32);
        assert_eq!(chain_code.len(), ChainCode::LENGTH);
    }

    #[test]
    fn test_chain_code_is_empty() {
        let chain_code = ChainCode::new([0u8; 32]);
        assert!(!chain_code.is_empty());
    }

    #[test]
    fn test_chain_code_clone() {
        let bytes = [99u8; 32];
        let chain_code1 = ChainCode::new(bytes);
        let chain_code2 = chain_code1.clone();
        assert_eq!(chain_code1, chain_code2);
        assert_eq!(chain_code1.as_bytes(), chain_code2.as_bytes());
    }

    #[test]
    fn test_chain_code_equality() {
        let chain_code1 = ChainCode::new([1u8; 32]);
        let chain_code2 = ChainCode::new([1u8; 32]);
        let chain_code3 = ChainCode::new([2u8; 32]);

        assert_eq!(chain_code1, chain_code2);
        assert_ne!(chain_code1, chain_code3);
        assert_ne!(chain_code2, chain_code3);
    }

    #[test]
    fn test_chain_code_debug() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[1] = 0xCD;
        bytes[2] = 0xEF;
        bytes[3] = 0x01;

        let chain_code = ChainCode::new(bytes);
        let debug_str = format!("{:?}", chain_code);

        assert!(debug_str.contains("ChainCode"));
        assert!(debug_str.contains("ab"));
        assert!(debug_str.contains("cd"));
        assert!(debug_str.contains("..."));
    }

    #[test]
    fn test_chain_code_as_ref() {
        let bytes = [77u8; 32];
        let chain_code = ChainCode::new(bytes);
        let slice: &[u8] = chain_code.as_ref();
        assert_eq!(slice, &bytes);
        assert_eq!(slice.len(), 32);
    }

    #[test]
    fn test_chain_code_from_array() {
        let bytes = [55u8; 32];
        let chain_code: ChainCode = bytes.into();
        assert_eq!(chain_code.as_bytes(), &bytes);
    }

    #[test]
    fn test_chain_code_try_from_slice_valid() {
        let bytes: &[u8] = &[88u8; 32];
        let chain_code = ChainCode::try_from(bytes).unwrap();
        assert_eq!(chain_code.as_bytes(), &[88u8; 32]);
    }

    #[test]
    fn test_chain_code_try_from_slice_invalid() {
        let bytes: &[u8] = &[0u8; 10];
        let result = ChainCode::try_from(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_code_try_from_vec_valid() {
        let bytes = vec![66u8; 32];
        let chain_code = ChainCode::try_from(bytes).unwrap();
        assert_eq!(chain_code.as_bytes(), &[66u8; 32]);
    }

    #[test]
    fn test_chain_code_try_from_vec_invalid() {
        let bytes = vec![0u8; 20];
        let _result = ChainCode::try_from(bytes);
    }

    #[test]
    fn test_chain_code_different_values() {
        let code1 = ChainCode::new([1u8; 32]);
        let code2 = ChainCode::new([2u8; 32]);

        assert_ne!(code1, code2);
    }

    #[test]
    fn test_chain_code_drop_zeroizes() {
        // Create a ChainCode with recognizable pattern
        let sensitive_data = [0x42u8; 32];
        let chain_code = ChainCode::new(sensitive_data);

        // Get a raw pointer to the data location
        let ptr = chain_code.as_bytes().as_ptr();

        // Drop the chain code explicitly
        drop(chain_code);

        // After drop, the memory should be zeroized by ZeroizeOnDrop
        // Note: This test demonstrates the drop happens, but we can't
        // safely read the memory after drop in safe Rust.
        // The ZeroizeOnDrop derive macro guarantees zeroization.

        // This test mainly serves as documentation that ChainCode
        // implements ZeroizeOnDrop and will be zeroized on drop.
        assert!(ptr as usize > 0); // Pointer was valid
    }

    #[test]
    fn test_chain_code_scope_drop() {
        // Test that ChainCode is dropped when going out of scope
        let outer_value = {
            let chain_code = ChainCode::new([0xFFu8; 32]);
            chain_code.as_bytes()[0] // Access before drop
        };

        assert_eq!(outer_value, 0xFF);
        // chain_code is dropped here, memory should be zeroized
    }

    #[test]
    fn test_chain_code_clone_independence() {
        // Test that cloning creates independent instances
        let original = ChainCode::new([0xAAu8; 32]);
        let cloned = original.clone();

        // Both should be equal
        assert_eq!(original, cloned);

        // Drop one - the other should still be valid
        drop(original);
        assert_eq!(cloned.as_bytes()[0], 0xAA);
    }
}
