//! Wei type for EVM transaction values.
//!
//! Wei is the smallest unit of Ether/BNB. This module provides a wrapper
//! around U256 with convenient conversion methods.

use primitive_types::U256;
use std::fmt;
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;

use crate::{Error, Result};

/// The number of wei in one gwei (10^9).
pub const GWEI: u64 = 1_000_000_000;

/// The number of wei in one ether/BNB (10^18).
pub const ETHER: u64 = 1_000_000_000_000_000_000;

/// A value in wei (smallest EVM currency unit).
///
/// Wei is a wrapper around U256 that provides convenient methods for
/// working with EVM currency values.
///
/// # Unit Conversions
///
/// - 1 ether = 10^18 wei
/// - 1 gwei = 10^9 wei
/// - 1 wei = 1 wei
///
/// # Examples
///
/// ```rust
/// use khodpay_signing::Wei;
///
/// // Create from different units
/// let one_ether = Wei::from_ether(1);
/// let one_gwei = Wei::from_gwei(1);
/// let one_wei = Wei::from_wei(1u64);
///
/// // Arithmetic
/// let total = one_gwei + one_wei;
///
/// // Display
/// println!("{} wei", one_ether);  // 1000000000000000000 wei
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Wei(U256);

impl Wei {
    /// Zero wei.
    pub const ZERO: Wei = Wei(U256::zero());

    /// Creates a Wei value from a U256.
    pub const fn from_u256(value: U256) -> Self {
        Wei(value)
    }

    /// Creates a Wei value from wei (no conversion).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Wei;
    ///
    /// let value = Wei::from_wei(1000u64);
    /// assert_eq!(value.as_u64(), Some(1000));
    /// ```
    pub fn from_wei<T: Into<U256>>(wei: T) -> Self {
        Wei(wei.into())
    }

    /// Creates a Wei value from gwei.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Wei;
    ///
    /// let value = Wei::from_gwei(5);
    /// assert_eq!(value.as_u64(), Some(5_000_000_000));
    /// ```
    pub fn from_gwei(gwei: u64) -> Self {
        Wei(U256::from(gwei) * U256::from(GWEI))
    }

    /// Creates a Wei value from ether/BNB.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Wei;
    ///
    /// let value = Wei::from_ether(1);
    /// assert_eq!(value.to_string(), "1000000000000000000");
    /// ```
    pub fn from_ether(ether: u64) -> Self {
        Wei(U256::from(ether) * U256::from(ETHER))
    }

    /// Returns the value as U256.
    pub const fn as_u256(&self) -> U256 {
        self.0
    }

    /// Returns the value as u64 if it fits.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Wei;
    ///
    /// let small = Wei::from_wei(1000u64);
    /// assert_eq!(small.as_u64(), Some(1000));
    ///
    /// let large = Wei::from_ether(1000000000000);
    /// assert_eq!(large.as_u64(), None);  // Too large for u64
    /// ```
    pub fn as_u64(&self) -> Option<u64> {
        if self.0 <= U256::from(u64::MAX) {
            Some(self.0.as_u64())
        } else {
            None
        }
    }

    /// Returns the value as u128 if it fits.
    pub fn as_u128(&self) -> Option<u128> {
        if self.0 <= U256::from(u128::MAX) {
            Some(self.0.as_u128())
        } else {
            None
        }
    }

    /// Converts to gwei (truncates).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Wei;
    ///
    /// let value = Wei::from_gwei(5);
    /// assert_eq!(value.to_gwei(), 5);
    /// ```
    pub fn to_gwei(&self) -> u64 {
        (self.0 / U256::from(GWEI)).as_u64()
    }

    /// Converts to ether (truncates).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Wei;
    ///
    /// let value = Wei::from_ether(5);
    /// assert_eq!(value.to_ether(), 5);
    /// ```
    pub fn to_ether(&self) -> u64 {
        (self.0 / U256::from(ETHER)).as_u64()
    }

    /// Returns `true` if the value is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Returns the value as a byte array in big-endian format.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.0.to_big_endian(&mut bytes);
        bytes
    }

    /// Creates a Wei value from big-endian bytes.
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        Wei(U256::from_big_endian(bytes))
    }
}

impl From<u64> for Wei {
    fn from(value: u64) -> Self {
        Wei::from_wei(value)
    }
}

impl From<u128> for Wei {
    fn from(value: u128) -> Self {
        Wei::from_wei(value)
    }
}

impl From<U256> for Wei {
    fn from(value: U256) -> Self {
        Wei(value)
    }
}

impl From<Wei> for U256 {
    fn from(wei: Wei) -> Self {
        wei.0
    }
}

impl Add for Wei {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Wei(self.0 + rhs.0)
    }
}

impl Sub for Wei {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Wei(self.0 - rhs.0)
    }
}

impl Mul<u64> for Wei {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        Wei(self.0 * U256::from(rhs))
    }
}

impl FromStr for Wei {
    type Err = Error;

    /// Parses a Wei value from a decimal string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Wei;
    ///
    /// let value: Wei = "1000000000".parse().unwrap();
    /// assert_eq!(value, Wei::from_gwei(1));
    /// ```
    fn from_str(s: &str) -> Result<Self> {
        U256::from_dec_str(s)
            .map(Wei)
            .map_err(|e| Error::InvalidValue(e.to_string()))
    }
}

impl fmt::Display for Wei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Wei {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Wei({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Construction Tests ====================

    #[test]
    fn test_from_wei() {
        let value = Wei::from_wei(1000u64);
        assert_eq!(value.as_u64(), Some(1000));
    }

    #[test]
    fn test_from_gwei() {
        let value = Wei::from_gwei(1);
        assert_eq!(value.as_u64(), Some(1_000_000_000));
    }

    #[test]
    fn test_from_gwei_multiple() {
        let value = Wei::from_gwei(5);
        assert_eq!(value.as_u64(), Some(5_000_000_000));
    }

    #[test]
    fn test_from_ether() {
        let value = Wei::from_ether(1);
        assert_eq!(value.as_u64(), Some(1_000_000_000_000_000_000));
    }

    #[test]
    fn test_from_ether_multiple() {
        let value = Wei::from_ether(2);
        assert_eq!(value.as_u64(), Some(2_000_000_000_000_000_000));
    }

    #[test]
    fn test_zero() {
        assert!(Wei::ZERO.is_zero());
        assert_eq!(Wei::ZERO.as_u64(), Some(0));
    }

    // ==================== Conversion Tests ====================

    #[test]
    fn test_to_gwei() {
        let value = Wei::from_gwei(5);
        assert_eq!(value.to_gwei(), 5);
    }

    #[test]
    fn test_to_gwei_truncates() {
        let value = Wei::from_wei(5_500_000_000u64);
        assert_eq!(value.to_gwei(), 5); // Truncates 0.5 gwei
    }

    #[test]
    fn test_to_ether() {
        let value = Wei::from_ether(5);
        assert_eq!(value.to_ether(), 5);
    }

    #[test]
    fn test_to_ether_truncates() {
        let value = Wei::from_gwei(1_500_000_000); // 1.5 ether
        assert_eq!(value.to_ether(), 1); // Truncates 0.5 ether
    }

    #[test]
    fn test_as_u64_overflow() {
        let large = Wei::from_ether(100) * 1_000_000_000;
        assert_eq!(large.as_u64(), None);
    }

    #[test]
    fn test_as_u128() {
        let value = Wei::from_ether(1);
        assert_eq!(value.as_u128(), Some(1_000_000_000_000_000_000u128));
    }

    // ==================== Arithmetic Tests ====================

    #[test]
    fn test_add() {
        let a = Wei::from_gwei(1);
        let b = Wei::from_gwei(2);
        let sum = a + b;
        assert_eq!(sum, Wei::from_gwei(3));
    }

    #[test]
    fn test_sub() {
        let a = Wei::from_gwei(5);
        let b = Wei::from_gwei(2);
        let diff = a - b;
        assert_eq!(diff, Wei::from_gwei(3));
    }

    #[test]
    fn test_mul() {
        let a = Wei::from_gwei(5);
        let product = a * 3;
        assert_eq!(product, Wei::from_gwei(15));
    }

    // ==================== Parsing Tests ====================

    #[test]
    fn test_from_str() {
        let value: Wei = "1000000000".parse().unwrap();
        assert_eq!(value, Wei::from_gwei(1));
    }

    #[test]
    fn test_from_str_large() {
        let value: Wei = "1000000000000000000".parse().unwrap();
        assert_eq!(value, Wei::from_ether(1));
    }

    #[test]
    fn test_from_str_invalid() {
        assert!("not_a_number".parse::<Wei>().is_err());
    }

    // ==================== Display Tests ====================

    #[test]
    fn test_display() {
        let value = Wei::from_gwei(1);
        assert_eq!(format!("{}", value), "1000000000");
    }

    #[test]
    fn test_debug() {
        let value = Wei::from_gwei(1);
        assert_eq!(format!("{:?}", value), "Wei(1000000000)");
    }

    // ==================== Bytes Tests ====================

    #[test]
    fn test_to_be_bytes() {
        let value = Wei::from_wei(256u64);
        let bytes = value.to_be_bytes();
        assert_eq!(bytes[30], 1);
        assert_eq!(bytes[31], 0);
    }

    #[test]
    fn test_from_be_bytes() {
        let mut bytes = [0u8; 32];
        bytes[31] = 100;
        let value = Wei::from_be_bytes(&bytes);
        assert_eq!(value.as_u64(), Some(100));
    }

    #[test]
    fn test_bytes_round_trip() {
        let original = Wei::from_ether(123);
        let bytes = original.to_be_bytes();
        let recovered = Wei::from_be_bytes(&bytes);
        assert_eq!(original, recovered);
    }

    // ==================== Equality Tests ====================

    #[test]
    fn test_equality() {
        let a = Wei::from_gwei(5);
        let b = Wei::from_gwei(5);
        let c = Wei::from_gwei(10);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_ordering() {
        let a = Wei::from_gwei(5);
        let b = Wei::from_gwei(10);

        assert!(a < b);
        assert!(b > a);
    }

    // ==================== From Trait Tests ====================

    #[test]
    fn test_from_u64() {
        let value: Wei = 1000u64.into();
        assert_eq!(value.as_u64(), Some(1000));
    }

    #[test]
    fn test_from_u128() {
        let value: Wei = 1000u128.into();
        assert_eq!(value.as_u128(), Some(1000));
    }

    #[test]
    fn test_from_u256() {
        let u256 = U256::from(1000);
        let value: Wei = u256.into();
        assert_eq!(value.as_u64(), Some(1000));
    }

    #[test]
    fn test_into_u256() {
        let value = Wei::from_wei(1000u64);
        let u256: U256 = value.into();
        assert_eq!(u256, U256::from(1000));
    }

    // ==================== Hash Tests ====================

    #[test]
    fn test_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(Wei::from_gwei(1));
        set.insert(Wei::from_gwei(2));

        assert!(set.contains(&Wei::from_gwei(1)));
        assert!(set.contains(&Wei::from_gwei(2)));
        assert!(!set.contains(&Wei::from_gwei(3)));
    }
}
