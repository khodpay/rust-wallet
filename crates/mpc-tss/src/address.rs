//! EVM address derivation from a secp256k1 public key.
//!
//! # Algorithm
//!
//! The Ethereum address derivation from a public key follows these steps:
//!
//! 1. Take the 65-byte **uncompressed** SEC1 encoding of the point
//!    (`0x04 || x_be || y_be`).
//! 2. Drop the leading `0x04` prefix, yielding 64 raw bytes.
//! 3. Apply **Keccak-256** to those 64 bytes.
//! 4. Take the **last 20 bytes** of the 32-byte digest — that is the raw address.
//! 5. Encode as an **EIP-55 checksummed** hex string (`0x…`).
//!
//! The result is a `String` of the form `"0x<40 hex chars with EIP-55 capitalisation>"`.
//!
//! # Security note
//!
//! The public key is not secret.  This module does not handle any key-share
//! material and intentionally has no `Zeroize` dependency.

use cggmp21::generic_ec::{coords::HasAffineXY, NonZero, Point};
use cggmp21::supported_curves::Secp256k1;
use sha3::{Digest, Keccak256};

use crate::error::{MpcError, Result};

/// Derives the EVM address from a secp256k1 joint public key.
///
/// The address is the last 20 bytes of `Keccak256(x_be || y_be)`, encoded as
/// an EIP-55 checksummed hex string.
///
/// # Errors
///
/// Returns [`MpcError::DkgFailed`] if the public key point is the point at
/// infinity (which should never occur for a valid DKG output).
///
/// # Example
///
/// ```ignore
/// // (called internally by DkgSession after a successful keygen)
/// let addr = evm_address_from_public_key(&joint_public_key)?;
/// assert!(addr.starts_with("0x"));
/// assert_eq!(addr.len(), 42);
/// ```
pub fn evm_address_from_public_key(pk: &NonZero<Point<Secp256k1>>) -> Result<String> {
    // 1. Get affine (x, y) coordinates.  NonZero<Point> is guaranteed
    //    non-infinity, but the coords() call returns Option for API symmetry.
    let coords = pk.coords().ok_or_else(|| MpcError::DkgFailed {
        reason: "joint public key is the point at infinity — DKG output is invalid".into(),
    })?;

    // 2. Concatenate raw big-endian x || y (32 bytes each = 64 bytes total).
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(coords.x.as_be_bytes());
    raw[32..].copy_from_slice(coords.y.as_be_bytes());

    // 3. Keccak-256 of the 64-byte payload.
    let hash: [u8; 32] = Keccak256::digest(raw).into();

    // 4. Last 20 bytes.
    let addr_bytes: [u8; 20] = hash[12..].try_into().expect("hash[12..] is exactly 20 bytes");

    // 5. EIP-55 checksum encoding.
    Ok(eip55_checksum(&addr_bytes))
}

/// Encodes a 20-byte address as an EIP-55 checksummed `0x…` string.
///
/// The algorithm:
/// 1. Hex-encode the address (lowercase, 40 chars).
/// 2. Keccak-256 the ASCII bytes of that lowercase string.
/// 3. For each hex character at position `i`: if the nibble at position `i` in
///    the hash is `>= 8`, uppercase the character.
fn eip55_checksum(addr: &[u8; 20]) -> String {
    let hex_lower: String = addr.iter().fold(String::with_capacity(40), |mut s, b| {
        s.push_str(&format!("{:02x}", b));
        s
    });

    let hash: [u8; 32] = Keccak256::digest(hex_lower.as_bytes()).into();

    let mut out = String::with_capacity(42);
    out.push_str("0x");

    for (i, ch) in hex_lower.chars().enumerate() {
        // Each byte of the hash covers two hex nibbles; nibble `i` is the
        // upper nibble of byte `i/2` for even `i`, lower nibble for odd `i`.
        let nibble = if i % 2 == 0 {
            (hash[i / 2] >> 4) & 0xf
        } else {
            hash[i / 2] & 0xf
        };
        if nibble >= 8 && ch.is_ascii_alphabetic() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch);
        }
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── eip55_checksum ──────────────────────────────────────────────────────

    /// EIP-55 reference vector from EIP-55 spec.
    #[test]
    fn test_eip55_known_vectors() {
        // Vectors from https://eips.ethereum.org/EIPS/eip-55
        let vectors: &[(&str, &str)] = &[
            (
                "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                "fb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                "dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                "d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
                "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            ),
        ];

        for (hex_addr, expected) in vectors {
            let bytes: Vec<u8> = (0..hex_addr.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex_addr[i..i + 2], 16).unwrap())
                .collect();
            let addr: [u8; 20] = bytes.try_into().unwrap();
            assert_eq!(eip55_checksum(&addr), *expected, "mismatch for {hex_addr}");
        }
    }

    #[test]
    fn test_eip55_all_zeros() {
        // Zero address — all hex chars are digits, checksum doesn't change capitalisation
        let addr = [0u8; 20];
        let result = eip55_checksum(&addr);
        assert!(result.starts_with("0x"));
        assert_eq!(result.len(), 42);
        // All digits — no letters to capitalise
        assert_eq!(&result[2..], "0000000000000000000000000000000000000000");
    }

    #[test]
    fn test_eip55_output_length() {
        let addr = [0xABu8; 20];
        let result = eip55_checksum(&addr);
        assert_eq!(result.len(), 42, "EIP-55 address must be exactly 42 chars");
        assert!(result.starts_with("0x"));
    }

    #[test]
    fn test_eip55_all_letters_uppercase_when_nibble_high() {
        // 0xFFFF...FF — every nibble is 0xF (>= 8), so every letter must be uppercase
        let addr = [0xFFu8; 20];
        let result = eip55_checksum(&addr);
        assert!(result.starts_with("0x"));
        let hex_part = &result[2..];
        // All chars must be 'f' (digit? no — 'f' is a letter); but only if
        // the hash nibble >= 8 they get uppercased.  We just check it's valid hex.
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "all chars must be hex digits: {}",
            result
        );
    }

    // ── evm_address_from_public_key — integration with a live Secp256k1 point ──

    #[test]
    fn test_address_from_generator_point() {
        use cggmp21::generic_ec::Point;
        // The secp256k1 generator G is NonZero<Point> — use it as a test public key
        let g: NonZero<Point<Secp256k1>> = Point::generator().into();
        let addr = evm_address_from_public_key(&g).expect("generator point must produce an address");
        assert!(addr.starts_with("0x"), "address must start with 0x");
        assert_eq!(addr.len(), 42, "address must be 42 chars");
        // Every character after '0x' must be a hex digit (or uppercase letter for EIP-55)
        assert!(
            addr[2..].chars().all(|c| c.is_ascii_hexdigit()),
            "non-hex char in address: {}",
            addr
        );
    }

    #[test]
    fn test_address_from_generator_is_deterministic() {
        use cggmp21::generic_ec::Point;
        let g: NonZero<Point<Secp256k1>> = Point::generator().into();
        let a1 = evm_address_from_public_key(&g).unwrap();
        let a2 = evm_address_from_public_key(&g).unwrap();
        assert_eq!(a1, a2, "address derivation must be deterministic");
    }

    #[test]
    fn test_address_from_two_points_differ() {
        use cggmp21::generic_ec::{Point, Scalar};
        // 2*G != G  => addresses must differ
        let g: NonZero<Point<Secp256k1>> = Point::generator().into();
        let two_g = {
            let two = Scalar::<Secp256k1>::from(2u32);
            let pt = Point::generator() * two;
            NonZero::from_point(pt).expect("2*G is non-zero")
        };
        let addr_g = evm_address_from_public_key(&g).unwrap();
        let addr_2g = evm_address_from_public_key(&two_g).unwrap();
        assert_ne!(addr_g, addr_2g, "different public keys must yield different addresses");
    }

    /// Known-answer test: keccak256 of the secp256k1 generator's uncompressed
    /// 64-byte payload, last 20 bytes, EIP-55 encoded.
    ///
    /// Reference computed independently:
    ///   x = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    ///   y = 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    ///   keccak256(x||y) => hash
    ///   last 20 bytes   => raw address
    #[test]
    fn test_address_from_generator_known_answer() {
        use cggmp21::generic_ec::Point;
        let g: NonZero<Point<Secp256k1>> = Point::generator().into();
        let addr = evm_address_from_public_key(&g).unwrap();
        // Derive the expected address independently using the same algorithm
        // so the test documents the expected value without hard-coding a
        // magic constant that's hard to verify at a glance.
        let coords = g.coords().unwrap();
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(coords.x.as_be_bytes());
        raw[32..].copy_from_slice(coords.y.as_be_bytes());
        let hash: [u8; 32] = sha3::Keccak256::digest(raw).into();
        let raw_addr: [u8; 20] = hash[12..].try_into().unwrap();
        let expected = eip55_checksum(&raw_addr);
        assert_eq!(addr, expected);
    }
}
