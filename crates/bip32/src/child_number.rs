//! Child number types for BIP-32 key derivation.
//!
//! This module provides the `ChildNumber` enum which represents an index used
//! in BIP-32 hierarchical key derivation. Child numbers can be either "normal"
//! (non-hardened) or "hardened".
//!
//! NOTE: This is a minimal definition to support DerivationPath (Task 25).
//! Full implementation will be added in Task 26-28.

/// A child number for BIP-32 key derivation.
///
/// Child numbers can be either:
/// - **Normal (Non-hardened)**: Allows deriving public child keys from public parent keys
/// - **Hardened**: Requires the private parent key; more secure but less flexible
///
/// The hardened bit (2^31) determines the type:
/// - `0` to `2^31-1` (0 to 2,147,483,647): Normal child numbers
/// - `2^31` to `2^32-1` (2,147,483,648 to 4,294,967,295): Hardened child numbers
///
/// # Notation
///
/// In BIP-32 path notation:
/// - `0` represents Normal(0)
/// - `0'` or `0h` represents Hardened(0)
/// - `44'` represents Hardened(44)
///
/// # Examples
///
/// ```rust,ignore
/// use bip32::ChildNumber;
///
/// // Normal child number
/// let normal = ChildNumber::Normal(0);
///
/// // Hardened child number (often written as 44')
/// let hardened = ChildNumber::Hardened(44);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildNumber {
    /// Normal (non-hardened) derivation.
    ///
    /// Index range: 0 to 2^31-1 (0x00000000 to 0x7FFFFFFF)
    ///
    /// Normal derivation allows deriving child public keys from the parent
    /// public key without needing the private key.
    Normal(u32),

    /// Hardened derivation.
    ///
    /// Index range: 0 to 2^31-1 (stored value, actual index is value + 2^31)
    ///
    /// Hardened derivation requires the parent private key and provides
    /// better security by preventing public key derivation.
    Hardened(u32),
}
