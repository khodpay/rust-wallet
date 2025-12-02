//! EVM address type with hex parsing and EIP-55 checksum support.
//!
//! An EVM address is a 20-byte identifier derived from the last 20 bytes of
//! the Keccak-256 hash of the public key.

use crate::{Error, Result};
use sha3::{Digest, Keccak256};
use std::fmt;
use std::str::FromStr;

/// A 20-byte EVM address.
///
/// Addresses are derived from public keys using Keccak-256 hashing.
/// They can be displayed with EIP-55 mixed-case checksum encoding.
///
/// # Examples
///
/// ```rust
/// use khodpay_signing::Address;
///
/// // Parse from hex string
/// let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".parse().unwrap();
///
/// // Display with checksum
/// println!("{}", addr);  // 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Address([u8; 20]);

impl Address {
    /// The length of an address in bytes.
    pub const LENGTH: usize = 20;

    /// The zero address (0x0000...0000).
    pub const ZERO: Address = Address([0u8; 20]);

    /// Creates an address from a 20-byte array.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Address;
    ///
    /// let bytes = [0u8; 20];
    /// let addr = Address::from_bytes(bytes);
    /// assert_eq!(addr, Address::ZERO);
    /// ```
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }

    /// Creates an address from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly 20 bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Address;
    ///
    /// let bytes = vec![0u8; 20];
    /// let addr = Address::from_slice(&bytes).unwrap();
    /// assert_eq!(addr, Address::ZERO);
    /// ```
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != Self::LENGTH {
            return Err(Error::InvalidAddress(format!(
                "expected {} bytes, got {}",
                Self::LENGTH,
                slice.len()
            )));
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(slice);
        Ok(Address(bytes))
    }

    /// Derives an address from an uncompressed public key (64 bytes, without 0x04 prefix).
    ///
    /// The address is the last 20 bytes of the Keccak-256 hash of the public key.
    ///
    /// # Arguments
    ///
    /// * `pubkey` - 64-byte uncompressed public key (x and y coordinates)
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is not exactly 64 bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Address;
    ///
    /// // Example public key (64 bytes)
    /// let pubkey = [0u8; 64];
    /// let addr = Address::from_public_key_bytes(&pubkey).unwrap();
    /// ```
    pub fn from_public_key_bytes(pubkey: &[u8]) -> Result<Self> {
        if pubkey.len() != 64 {
            return Err(Error::InvalidAddress(format!(
                "public key must be 64 bytes (uncompressed without prefix), got {}",
                pubkey.len()
            )));
        }

        let hash = Keccak256::digest(pubkey);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..32]);
        Ok(Address(address))
    }

    /// Returns the address as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Returns the address as a byte array.
    pub fn to_bytes(&self) -> [u8; 20] {
        self.0
    }

    /// Returns the EIP-55 checksummed hex string (with 0x prefix).
    ///
    /// EIP-55 uses mixed-case hex encoding where the case of each letter
    /// is determined by the corresponding nibble in the Keccak-256 hash
    /// of the lowercase address.
    pub fn to_checksum_string(&self) -> String {
        let hex_addr = hex::encode(self.0);
        let hash = Keccak256::digest(hex_addr.as_bytes());

        let mut checksum = String::with_capacity(42);
        checksum.push_str("0x");

        for (i, c) in hex_addr.chars().enumerate() {
            if c.is_ascii_digit() {
                checksum.push(c);
            } else {
                // Get the corresponding nibble from the hash
                let hash_byte = hash[i / 2];
                let hash_nibble = if i % 2 == 0 {
                    hash_byte >> 4
                } else {
                    hash_byte & 0x0f
                };

                if hash_nibble >= 8 {
                    checksum.push(c.to_ascii_uppercase());
                } else {
                    checksum.push(c.to_ascii_lowercase());
                }
            }
        }

        checksum
    }

    /// Validates an EIP-55 checksummed address string.
    ///
    /// Returns `true` if the address has valid checksum or is all lowercase/uppercase.
    pub fn validate_checksum(s: &str) -> bool {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() != 40 {
            return false;
        }

        // All lowercase or all uppercase is valid (no checksum)
        let is_all_lower = s.chars().all(|c| !c.is_ascii_uppercase());
        let is_all_upper = s.chars().all(|c| !c.is_ascii_lowercase());
        if is_all_lower || is_all_upper {
            return true;
        }

        // Validate mixed-case checksum
        let lower = s.to_lowercase();
        let hash = Keccak256::digest(lower.as_bytes());

        for (i, c) in s.chars().enumerate() {
            if c.is_ascii_alphabetic() {
                let hash_byte = hash[i / 2];
                let hash_nibble = if i % 2 == 0 {
                    hash_byte >> 4
                } else {
                    hash_byte & 0x0f
                };

                let should_be_upper = hash_nibble >= 8;
                if should_be_upper != c.is_ascii_uppercase() {
                    return false;
                }
            }
        }

        true
    }
}

impl FromStr for Address {
    type Err = Error;

    /// Parses an address from a hex string.
    ///
    /// Accepts both checksummed and non-checksummed addresses.
    /// The `0x` prefix is optional.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Address;
    ///
    /// // With 0x prefix
    /// let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".parse().unwrap();
    ///
    /// // Without prefix
    /// let addr: Address = "742d35Cc6634C0532925a3b844Bc454e4438f44e".parse().unwrap();
    /// ```
    fn from_str(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);

        if s.len() != 40 {
            return Err(Error::InvalidAddress(format!(
                "expected 40 hex characters, got {}",
                s.len()
            )));
        }

        let bytes = hex::decode(s).map_err(|e| Error::InvalidAddress(e.to_string()))?;

        Self::from_slice(&bytes)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_checksum_string())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_checksum_string())
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }
}

impl From<Address> for [u8; 20] {
    fn from(addr: Address) -> Self {
        addr.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Construction Tests ====================

    #[test]
    fn test_from_bytes() {
        let bytes = [1u8; 20];
        let addr = Address::from_bytes(bytes);
        assert_eq!(addr.to_bytes(), bytes);
    }

    #[test]
    fn test_from_slice_valid() {
        let bytes = vec![2u8; 20];
        let addr = Address::from_slice(&bytes).unwrap();
        assert_eq!(addr.as_bytes(), &[2u8; 20]);
    }

    #[test]
    fn test_from_slice_invalid_length() {
        let bytes = vec![0u8; 19];
        assert!(Address::from_slice(&bytes).is_err());

        let bytes = vec![0u8; 21];
        assert!(Address::from_slice(&bytes).is_err());
    }

    #[test]
    fn test_zero_address() {
        assert_eq!(Address::ZERO.to_bytes(), [0u8; 20]);
    }

    // ==================== Parsing Tests ====================

    #[test]
    fn test_parse_with_prefix() {
        let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap();
        assert_eq!(
            addr.to_checksum_string(),
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        );
    }

    #[test]
    fn test_parse_without_prefix() {
        let addr: Address = "742d35Cc6634C0532925a3b844Bc454e4438f44e".parse().unwrap();
        assert_eq!(
            addr.to_checksum_string(),
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        );
    }

    #[test]
    fn test_parse_lowercase() {
        let addr: Address = "0x742d35cc6634c0532925a3b844bc454e4438f44e"
            .parse()
            .unwrap();
        // Should still produce checksummed output
        assert_eq!(
            addr.to_checksum_string(),
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        );
    }

    #[test]
    fn test_parse_uppercase() {
        let addr: Address = "0x742D35CC6634C0532925A3B844BC454E4438F44E"
            .parse()
            .unwrap();
        assert_eq!(
            addr.to_checksum_string(),
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        );
    }

    #[test]
    fn test_parse_invalid_length() {
        assert!("0x742d35".parse::<Address>().is_err());
        assert!("0x742d35Cc6634C0532925a3b844Bc454e4438f44e00"
            .parse::<Address>()
            .is_err());
    }

    #[test]
    fn test_parse_invalid_hex() {
        assert!("0x742d35Cc6634C0532925a3b844Bc454e4438fXXX"
            .parse::<Address>()
            .is_err());
    }

    // ==================== Checksum Tests ====================

    #[test]
    fn test_checksum_encoding() {
        // Known test vectors from EIP-55
        let test_cases = [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ];

        for expected in test_cases {
            let addr: Address = expected.parse().unwrap();
            assert_eq!(addr.to_checksum_string(), expected);
        }
    }

    #[test]
    fn test_validate_checksum_valid() {
        assert!(Address::validate_checksum(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        ));
        assert!(Address::validate_checksum(
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        ));
    }

    #[test]
    fn test_validate_checksum_all_lowercase() {
        assert!(Address::validate_checksum(
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
        ));
    }

    #[test]
    fn test_validate_checksum_all_uppercase() {
        assert!(Address::validate_checksum(
            "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED"
        ));
    }

    #[test]
    fn test_validate_checksum_invalid() {
        // Wrong case on one character
        assert!(!Address::validate_checksum(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"
        )); // Last 'd' should be lowercase
    }

    // ==================== Public Key Derivation Tests ====================

    #[test]
    fn test_from_public_key_bytes() {
        // Known test vector
        // Public key for private key: 0x0000000000000000000000000000000000000000000000000000000000000001
        let pubkey = hex::decode(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\
             483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        )
        .unwrap();

        let addr = Address::from_public_key_bytes(&pubkey).unwrap();
        assert_eq!(
            addr.to_checksum_string(),
            "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        );
    }

    #[test]
    fn test_from_public_key_bytes_invalid_length() {
        let pubkey = vec![0u8; 63];
        assert!(Address::from_public_key_bytes(&pubkey).is_err());

        let pubkey = vec![0u8; 65];
        assert!(Address::from_public_key_bytes(&pubkey).is_err());
    }

    // ==================== Display Tests ====================

    #[test]
    fn test_display() {
        let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap();
        assert_eq!(
            format!("{}", addr),
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        );
    }

    #[test]
    fn test_debug() {
        let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap();
        assert_eq!(
            format!("{:?}", addr),
            "Address(0x742d35Cc6634C0532925a3b844Bc454e4438f44e)"
        );
    }

    #[test]
    fn test_lower_hex() {
        let addr: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap();
        assert_eq!(
            format!("{:x}", addr),
            "742d35cc6634c0532925a3b844bc454e4438f44e"
        );
        assert_eq!(
            format!("{:#x}", addr),
            "0x742d35cc6634c0532925a3b844bc454e4438f44e"
        );
    }

    // ==================== Equality Tests ====================

    #[test]
    fn test_equality() {
        let addr1: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap();
        let addr2: Address = "0x742d35cc6634c0532925a3b844bc454e4438f44e"
            .parse()
            .unwrap();
        let addr3: Address = "0x0000000000000000000000000000000000000000"
            .parse()
            .unwrap();

        assert_eq!(addr1, addr2);
        assert_ne!(addr1, addr3);
        assert_eq!(addr3, Address::ZERO);
    }

    // ==================== Conversion Tests ====================

    #[test]
    fn test_from_array() {
        let bytes = [3u8; 20];
        let addr: Address = bytes.into();
        assert_eq!(addr.to_bytes(), bytes);
    }

    #[test]
    fn test_into_array() {
        let addr = Address::from_bytes([4u8; 20]);
        let bytes: [u8; 20] = addr.into();
        assert_eq!(bytes, [4u8; 20]);
    }

    #[test]
    fn test_as_ref() {
        let addr = Address::from_bytes([5u8; 20]);
        let slice: &[u8] = addr.as_ref();
        assert_eq!(slice, &[5u8; 20]);
    }

    // ==================== Hash Tests ====================

    #[test]
    fn test_hash() {
        use std::collections::HashSet;

        let addr1: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap();
        let addr2: Address = "0x0000000000000000000000000000000000000000"
            .parse()
            .unwrap();

        let mut set = HashSet::new();
        set.insert(addr1);
        set.insert(addr2);

        assert!(set.contains(&addr1));
        assert!(set.contains(&addr2));
        assert_eq!(set.len(), 2);
    }
}
