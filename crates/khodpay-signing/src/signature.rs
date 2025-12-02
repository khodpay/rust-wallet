//! ECDSA signature types for EVM transactions.
//!
//! This module provides the `Signature` struct representing an ECDSA signature
//! with recovery ID, as used in Ethereum-compatible transactions.

use std::fmt;
use zeroize::Zeroize;

/// An ECDSA signature with recovery ID.
///
/// EVM transactions use secp256k1 ECDSA signatures with a recovery ID (`v`)
/// that allows recovering the public key (and thus the sender address) from
/// the signature.
///
/// # Fields
///
/// - `r`: The R component of the signature (32 bytes)
/// - `s`: The S component of the signature (32 bytes)  
/// - `v`: The recovery ID (0 or 1 for EIP-1559 transactions)
///
/// # Note
///
/// For EIP-1559 transactions, `v` is simply the recovery ID (0 or 1),
/// not the legacy `v = 27 + recovery_id` or EIP-155 `v = chain_id * 2 + 35 + recovery_id`.
///
/// # Security
///
/// The signature implements `Zeroize` to clear sensitive data from memory when dropped.
#[derive(Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct Signature {
    /// The R component of the signature.
    pub r: [u8; 32],
    /// The S component of the signature.
    pub s: [u8; 32],
    /// The recovery ID (0 or 1).
    pub v: u8,
}

impl Signature {
    /// Creates a new signature from components.
    ///
    /// # Arguments
    ///
    /// * `r` - The R component (32 bytes)
    /// * `s` - The S component (32 bytes)
    /// * `v` - The recovery ID (0 or 1)
    pub const fn new(r: [u8; 32], s: [u8; 32], v: u8) -> Self {
        Self { r, s, v }
    }

    /// Creates a signature from raw bytes (65 bytes: r || s || v).
    ///
    /// # Errors
    ///
    /// Returns `None` if the slice is not exactly 65 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 65 {
            return None;
        }

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        let v = bytes[64];

        Some(Self { r, s, v })
    }

    /// Returns the signature as raw bytes (65 bytes: r || s || v).
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes[64] = self.v;
        bytes
    }

    /// Returns the R component as a big-endian U256.
    pub fn r_as_bytes(&self) -> &[u8; 32] {
        &self.r
    }

    /// Returns the S component as a big-endian U256.
    pub fn s_as_bytes(&self) -> &[u8; 32] {
        &self.s
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("r", &hex::encode(self.r))
            .field("s", &hex::encode(self.s))
            .field("v", &self.v)
            .finish()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{}{}{}",
            hex::encode(self.r),
            hex::encode(self.s),
            hex::encode([self.v])
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signature() -> Signature {
        Signature::new([1u8; 32], [2u8; 32], 0)
    }

    // ==================== Construction Tests ====================

    #[test]
    fn test_new() {
        let r = [1u8; 32];
        let s = [2u8; 32];
        let v = 1;

        let sig = Signature::new(r, s, v);

        assert_eq!(sig.r, r);
        assert_eq!(sig.s, s);
        assert_eq!(sig.v, v);
    }

    #[test]
    fn test_from_bytes_valid() {
        let mut bytes = [0u8; 65];
        bytes[0..32].copy_from_slice(&[1u8; 32]);
        bytes[32..64].copy_from_slice(&[2u8; 32]);
        bytes[64] = 1;

        let sig = Signature::from_bytes(&bytes).unwrap();

        assert_eq!(sig.r, [1u8; 32]);
        assert_eq!(sig.s, [2u8; 32]);
        assert_eq!(sig.v, 1);
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        assert!(Signature::from_bytes(&[0u8; 64]).is_none());
        assert!(Signature::from_bytes(&[0u8; 66]).is_none());
        assert!(Signature::from_bytes(&[]).is_none());
    }

    // ==================== Serialization Tests ====================

    #[test]
    fn test_to_bytes() {
        let sig = test_signature();
        let bytes = sig.to_bytes();

        assert_eq!(bytes.len(), 65);
        assert_eq!(&bytes[0..32], &[1u8; 32]);
        assert_eq!(&bytes[32..64], &[2u8; 32]);
        assert_eq!(bytes[64], 0);
    }

    #[test]
    fn test_round_trip() {
        let original = Signature::new([3u8; 32], [4u8; 32], 1);
        let bytes = original.to_bytes();
        let recovered = Signature::from_bytes(&bytes).unwrap();

        assert_eq!(original, recovered);
    }

    // ==================== Accessor Tests ====================

    #[test]
    fn test_r_as_bytes() {
        let sig = test_signature();
        assert_eq!(sig.r_as_bytes(), &[1u8; 32]);
    }

    #[test]
    fn test_s_as_bytes() {
        let sig = test_signature();
        assert_eq!(sig.s_as_bytes(), &[2u8; 32]);
    }

    // ==================== Display Tests ====================

    #[test]
    fn test_display() {
        let sig = Signature::new([0u8; 32], [0u8; 32], 0);
        let display = format!("{}", sig);

        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 2 + 64 + 64 + 2); // 0x + r + s + v
    }

    #[test]
    fn test_debug() {
        let sig = test_signature();
        let debug = format!("{:?}", sig);

        assert!(debug.contains("Signature"));
        assert!(debug.contains("r:"));
        assert!(debug.contains("s:"));
        assert!(debug.contains("v:"));
    }

    // ==================== Equality Tests ====================

    #[test]
    fn test_equality() {
        let sig1 = Signature::new([1u8; 32], [2u8; 32], 0);
        let sig2 = Signature::new([1u8; 32], [2u8; 32], 0);
        let sig3 = Signature::new([1u8; 32], [2u8; 32], 1);

        assert_eq!(sig1, sig2);
        assert_ne!(sig1, sig3);
    }

    #[test]
    fn test_clone() {
        let sig = test_signature();
        let cloned = sig.clone();

        assert_eq!(sig, cloned);
    }

    // ==================== Recovery ID Tests ====================

    #[test]
    fn test_v_zero() {
        let sig = Signature::new([0u8; 32], [0u8; 32], 0);
        assert_eq!(sig.v, 0);
    }

    #[test]
    fn test_v_one() {
        let sig = Signature::new([0u8; 32], [0u8; 32], 1);
        assert_eq!(sig.v, 1);
    }

    // ==================== Zeroize Tests ====================

    #[test]
    fn test_zeroize() {
        use zeroize::Zeroize;
        
        let mut sig = Signature::new([0xab; 32], [0xcd; 32], 1);
        sig.zeroize();
        
        assert_eq!(sig.r, [0u8; 32]);
        assert_eq!(sig.s, [0u8; 32]);
        assert_eq!(sig.v, 0);
    }
}
