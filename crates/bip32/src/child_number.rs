//! Child number types for BIP-32 key derivation.
//!
//! This module provides the `ChildNumber` enum which represents an index used
//! in BIP-32 hierarchical key derivation. Child numbers can be either "normal"
//! (non-hardened) or "hardened".
//!
//! # Hardened vs Normal Derivation
//!
//! BIP-32 defines two types of child key derivation:
//!
//! ## Normal (Non-Hardened) Derivation
//!
//! - Uses indices 0 to 2³¹-1 (0x00000000 to 0x7FFFFFFF)
//! - Allows deriving child **public** keys from parent **public** keys
//! - Useful for watch-only wallets and public key distribution
//! - More flexible but slightly less secure
//! - Notation: `0`, `1`, `2`, etc.
//!
//! ## Hardened Derivation
//!
//! - Uses indices 2³¹ to 2³²-1 (0x80000000 to 0xFFFFFFFF)
//! - Requires parent **private** key for derivation
//! - Cannot derive child public keys from parent public key
//! - More secure, prevents exposure of parent chain
//! - Notation: `0'`, `1'`, `44'`, etc. (or `0h`, `1h`, `44h`)
//!
//! # Security Consideration
//!
//! If a child private key is compromised along with the parent chain code,
//! an attacker can derive the parent private key in **normal** derivation.
//! **Hardened** derivation prevents this attack vector.
//!
//! # BIP-44 Usage Example
//!
//! BIP-44 defines: `m / purpose' / coin_type' / account' / change / address_index`
//!
//! - `purpose'`, `coin_type'`, `account'`: Hardened (more secure for upper levels)
//! - `change`, `address_index`: Normal (allows generating addresses without private key)

/// A child number for BIP-32 key derivation.
///
/// Represents an index used to derive a child key from a parent key in the
/// BIP-32 hierarchical deterministic wallet structure.
///
/// # Variants
///
/// - **Normal**: Index 0 to 2³¹-1, allows public key derivation
/// - **Hardened**: Index 2³¹ to 2³²-1, requires private key, more secure
///
/// # Internal Representation
///
/// Both variants store the "base" index (0 to 2³¹-1):
/// - `Normal(n)`: Actual index is `n`
/// - `Hardened(n)`: Actual index is `n + 2³¹` (with hardened bit set)
///
/// # Notation in Derivation Paths
///
/// ```text
/// m/0/1/2      - All normal (indices 0, 1, 2)
/// m/0'/1'/2'   - All hardened (indices 2³¹+0, 2³¹+1, 2³¹+2)
/// m/44'/0'/0'  - Hardened (BIP-44 account level)
/// m/44'/0'/0'/0/0  - Mixed (upper hardened, lower normal)
/// ```
///
/// # Size and Limits
///
/// - Each variant stores a `u32` value
/// - Normal: Valid values 0 to 2,147,483,647 (0x7FFFFFFF)
/// - Hardened: Valid values 0 to 2,147,483,647 (stored, actual index + 2³¹)
/// - Size: 8 bytes (4 bytes for u32 + enum discriminant)
///
/// # Examples
///
/// ## Basic Usage
///
/// ```
/// use bip32::ChildNumber;
///
/// // Normal child numbers (for address generation)
/// let normal_0 = ChildNumber::Normal(0);
/// let normal_5 = ChildNumber::Normal(5);
///
/// assert!(!normal_0.is_hardened());
/// assert_eq!(normal_0.to_index(), 0);
/// assert_eq!(normal_5.to_index(), 5);
/// ```
///
/// ## Hardened Derivation
///
/// ```
/// use bip32::ChildNumber;
///
/// // Hardened child numbers (for account/coin levels)
/// let hardened_0 = ChildNumber::Hardened(0);   // Often written as 0'
/// let hardened_44 = ChildNumber::Hardened(44); // Often written as 44'
///
/// assert!(hardened_0.is_hardened());
/// assert_eq!(hardened_44.to_index(), 0x8000002C); // 2^31 + 44
/// ```
///
/// ## BIP-44 Path Components
///
/// ```
/// use bip32::ChildNumber;
///
/// // Building a BIP-44 path: m/44'/0'/0'/0/0
/// let purpose = ChildNumber::Hardened(44);     // m/44'
/// let coin_type = ChildNumber::Hardened(0);    // /0' (Bitcoin)
/// let account = ChildNumber::Hardened(0);      // /0' (first account)
/// let change = ChildNumber::Normal(0);         // /0 (external chain)
/// let index = ChildNumber::Normal(0);          // /0 (first address)
///
/// // Upper levels are hardened for security
/// assert!(purpose.is_hardened());
/// assert!(coin_type.is_hardened());
/// assert!(account.is_hardened());
///
/// // Lower levels are normal for watch-only wallets
/// assert!(!change.is_hardened());
/// assert!(!index.is_hardened());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ChildNumber {
    /// Normal (non-hardened) child derivation.
    ///
    /// **Index Range**: 0 to 2³¹-1 (0x00000000 to 0x7FFFFFFF)
    ///
    /// # Properties
    ///
    /// - Allows deriving child **public** keys from parent **public** key
    /// - Does not require parent private key for public key derivation
    /// - Used for address generation in BIP-44 `change` and `address_index` levels
    /// - Slightly less secure: if child private key + parent chain code leaked, parent can be derived
    ///
    /// # Use Cases
    ///
    /// - Address generation without exposing private keys
    /// - Watch-only wallets
    /// - Point-of-sale systems
    /// - Public key distribution
    ///
    /// # Notation
    ///
    /// In derivation paths: `m/0`, `m/1/2`, etc. (no apostrophe or 'h')
    Normal(u32),

    /// Hardened child derivation.
    ///
    /// **Index Range**: 0 to 2³¹-1 (stored value, actual index is value + 2³¹)
    ///
    /// **Actual Index**: 2³¹ to 2³²-1 (0x80000000 to 0xFFFFFFFF)
    ///
    /// # Properties
    ///
    /// - Requires parent **private** key for all derivations
    /// - Cannot derive child public keys from parent public key alone
    /// - Used for account-level derivation in BIP-44 `purpose`, `coin_type`, `account` levels
    /// - More secure: child key compromise doesn't reveal parent key
    ///
    /// # Use Cases
    ///
    /// - Account separation (different users, purposes)
    /// - Coin type identification (Bitcoin, Ethereum, etc.)
    /// - Top-level derivation where security is critical
    ///
    /// # Notation
    ///
    /// In derivation paths: `m/0'`, `m/44'/0'`, etc. (apostrophe or 'h' suffix)
    ///
    /// # Security Note
    ///
    /// Always use hardened derivation for upper levels of the tree (purpose, coin_type, account)
    /// to prevent key compromise from propagating up the hierarchy.
    Hardened(u32),
}

impl ChildNumber {
    /// The hardened bit flag (2³¹ = 0x80000000 = 2,147,483,648).
    ///
    /// This bit is set in the index to indicate hardened derivation.
    /// - If bit 31 is 0: Normal derivation (0x00000000 to 0x7FFFFFFF)
    /// - If bit 31 is 1: Hardened derivation (0x80000000 to 0xFFFFFFFF)
    pub const HARDENED_BIT: u32 = 0x80000000;

    /// Maximum value for a normal (non-hardened) child index.
    ///
    /// Equal to 2³¹ - 1 = 2,147,483,647 (0x7FFFFFFF).
    ///
    /// Any index above this value is considered hardened.
    pub const MAX_NORMAL_INDEX: u32 = Self::HARDENED_BIT - 1;

    /// Maximum value for the base index in either variant.
    ///
    /// Both Normal(n) and Hardened(n) must have n ≤ MAX_NORMAL_INDEX.
    /// Equal to 2³¹ - 1 = 2,147,483,647 (0x7FFFFFFF).
    pub const MAX_BASE_INDEX: u32 = Self::MAX_NORMAL_INDEX;

    /// Minimum hardened child index (actual index, not stored value).
    ///
    /// Equal to 2³¹ = 2,147,483,648 (0x80000000).
    ///
    /// This is `Hardened(0)` when converted to an index.
    pub const MIN_HARDENED_INDEX: u32 = Self::HARDENED_BIT;

    /// Maximum hardened child index (actual index, not stored value).
    ///
    /// Equal to 2³² - 1 = 4,294,967,295 (0xFFFFFFFF).
    ///
    /// This is `Hardened(2³¹ - 1)` when converted to an index.
    pub const MAX_HARDENED_INDEX: u32 = u32::MAX;

    /// Creates a `ChildNumber` from a raw u32 index.
    ///
    /// If the index has the hardened bit set (bit 31), creates a `Hardened` variant.
    /// Otherwise, creates a `Normal` variant.
    ///
    /// # Arguments
    ///
    /// * `index` - The raw index value (0 to 2³²-1)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::ChildNumber;
    ///
    /// // Normal indices
    /// let normal_0 = ChildNumber::from_index(0);
    /// assert_eq!(normal_0, ChildNumber::Normal(0));
    ///
    /// let normal_42 = ChildNumber::from_index(42);
    /// assert_eq!(normal_42, ChildNumber::Normal(42));
    ///
    /// // Hardened indices
    /// let hardened_0 = ChildNumber::from_index(0x80000000);
    /// assert_eq!(hardened_0, ChildNumber::Hardened(0));
    ///
    /// let hardened_44 = ChildNumber::from_index(0x8000002C);  // 2^31 + 44
    /// assert_eq!(hardened_44, ChildNumber::Hardened(44));
    /// ```
    pub fn from_index(index: u32) -> Self {
        if index & Self::HARDENED_BIT == 0 {
            // Bit 31 is not set: Normal derivation
            ChildNumber::Normal(index)
        } else {
            // Bit 31 is set: Hardened derivation
            // Remove the hardened bit to get the base index
            ChildNumber::Hardened(index & Self::MAX_NORMAL_INDEX)
        }
    }

    /// Converts this `ChildNumber` to a raw u32 index.
    ///
    /// For `Normal` variants, returns the value as-is.
    /// For `Hardened` variants, returns the value with the hardened bit set (value + 2³¹).
    ///
    /// # Returns
    ///
    /// The raw index value that would be used in BIP-32 key derivation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::ChildNumber;
    ///
    /// // Normal child numbers
    /// assert_eq!(ChildNumber::Normal(0).to_index(), 0);
    /// assert_eq!(ChildNumber::Normal(42).to_index(), 42);
    ///
    /// // Hardened child numbers
    /// assert_eq!(ChildNumber::Hardened(0).to_index(), 0x80000000);
    /// assert_eq!(ChildNumber::Hardened(44).to_index(), 0x8000002C);
    /// ```
    pub fn to_index(self) -> u32 {
        match self {
            ChildNumber::Normal(index) => index,
            ChildNumber::Hardened(index) => index | Self::HARDENED_BIT,
        }
    }

    /// Returns `true` if this is a normal (non-hardened) child number.
    ///
    /// Normal child numbers allow deriving child public keys from parent public keys
    /// without needing the private key.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::ChildNumber;
    ///
    /// assert!(ChildNumber::Normal(0).is_normal());
    /// assert!(ChildNumber::Normal(42).is_normal());
    /// assert!(!ChildNumber::Hardened(0).is_normal());
    /// ```
    pub fn is_normal(self) -> bool {
        matches!(self, ChildNumber::Normal(_))
    }

    /// Returns `true` if this is a hardened child number.
    ///
    /// Hardened child numbers require the parent private key for derivation and
    /// provide better security by preventing public key derivation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::ChildNumber;
    ///
    /// assert!(ChildNumber::Hardened(0).is_hardened());
    /// assert!(ChildNumber::Hardened(44).is_hardened());
    /// assert!(!ChildNumber::Normal(0).is_hardened());
    /// ```
    pub fn is_hardened(self) -> bool {
        matches!(self, ChildNumber::Hardened(_))
    }

    /// Returns the base value of this child number (without the hardened bit).
    ///
    /// For both `Normal` and `Hardened` variants, this returns the stored index value
    /// in the range 0 to 2³¹-1.
    ///
    /// # Returns
    ///
    /// - For `Normal(n)`: returns `n`
    /// - For `Hardened(n)`: returns `n` (not `n + 2³¹`)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::ChildNumber;
    ///
    /// // For normal, value() equals to_index()
    /// let normal = ChildNumber::Normal(42);
    /// assert_eq!(normal.value(), 42);
    /// assert_eq!(normal.value(), normal.to_index());
    ///
    /// // For hardened, value() is the base (without hardened bit)
    /// let hardened = ChildNumber::Hardened(44);
    /// assert_eq!(hardened.value(), 44);
    /// assert_eq!(hardened.to_index(), 0x8000002C);  // 2^31 + 44
    /// ```
    pub fn value(self) -> u32 {
        match self {
            ChildNumber::Normal(value) => value,
            ChildNumber::Hardened(value) => value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Constants Tests
    // ========================================================================

    #[test]
    fn test_constants_values() {
        assert_eq!(ChildNumber::HARDENED_BIT, 0x80000000);
        assert_eq!(ChildNumber::HARDENED_BIT, 2_147_483_648);

        assert_eq!(ChildNumber::MAX_NORMAL_INDEX, 0x7FFFFFFF);
        assert_eq!(ChildNumber::MAX_NORMAL_INDEX, 2_147_483_647);

        assert_eq!(ChildNumber::MAX_BASE_INDEX, 2_147_483_647);

        assert_eq!(ChildNumber::MIN_HARDENED_INDEX, 0x80000000);
        assert_eq!(ChildNumber::MIN_HARDENED_INDEX, 2_147_483_648);

        assert_eq!(ChildNumber::MAX_HARDENED_INDEX, 0xFFFFFFFF);
        assert_eq!(ChildNumber::MAX_HARDENED_INDEX, u32::MAX);
    }

    #[test]
    fn test_constants_relationships() {
        // MAX_NORMAL_INDEX is one less than HARDENED_BIT
        assert_eq!(ChildNumber::MAX_NORMAL_INDEX + 1, ChildNumber::HARDENED_BIT);

        // MIN_HARDENED_INDEX equals HARDENED_BIT
        assert_eq!(ChildNumber::MIN_HARDENED_INDEX, ChildNumber::HARDENED_BIT);

        // MAX_BASE_INDEX equals MAX_NORMAL_INDEX
        assert_eq!(ChildNumber::MAX_BASE_INDEX, ChildNumber::MAX_NORMAL_INDEX);
    }

    // ========================================================================
    // Creation Tests
    // ========================================================================

    #[test]
    fn test_normal_creation() {
        let normal_0 = ChildNumber::Normal(0);
        assert!(matches!(normal_0, ChildNumber::Normal(0)));

        let normal_max = ChildNumber::Normal(ChildNumber::MAX_NORMAL_INDEX);
        assert!(matches!(normal_max, ChildNumber::Normal(_)));
    }

    #[test]
    fn test_hardened_creation() {
        let hardened_0 = ChildNumber::Hardened(0);
        assert!(matches!(hardened_0, ChildNumber::Hardened(0)));

        let hardened_44 = ChildNumber::Hardened(44);
        assert!(matches!(hardened_44, ChildNumber::Hardened(44)));

        let hardened_max = ChildNumber::Hardened(ChildNumber::MAX_NORMAL_INDEX);
        assert!(matches!(hardened_max, ChildNumber::Hardened(_)));
    }

    // ========================================================================
    // Equality and Comparison Tests
    // ========================================================================

    #[test]
    fn test_equality() {
        assert_eq!(ChildNumber::Normal(0), ChildNumber::Normal(0));
        assert_eq!(ChildNumber::Normal(42), ChildNumber::Normal(42));
        assert_eq!(ChildNumber::Hardened(0), ChildNumber::Hardened(0));
        assert_eq!(ChildNumber::Hardened(44), ChildNumber::Hardened(44));
    }

    #[test]
    fn test_inequality() {
        assert_ne!(ChildNumber::Normal(0), ChildNumber::Normal(1));
        assert_ne!(ChildNumber::Hardened(0), ChildNumber::Hardened(1));
        assert_ne!(ChildNumber::Normal(0), ChildNumber::Hardened(0));
        assert_ne!(ChildNumber::Normal(44), ChildNumber::Hardened(44));
    }

    #[test]
    fn test_ordering() {
        // Normal variants order by their index
        assert!(ChildNumber::Normal(0) < ChildNumber::Normal(1));
        assert!(ChildNumber::Normal(1) < ChildNumber::Normal(100));

        // Hardened variants order by their index
        assert!(ChildNumber::Hardened(0) < ChildNumber::Hardened(1));
        assert!(ChildNumber::Hardened(1) < ChildNumber::Hardened(100));

        // Normal comes before Hardened (enum variant order)
        assert!(ChildNumber::Normal(0) < ChildNumber::Hardened(0));
        assert!(ChildNumber::Normal(999) < ChildNumber::Hardened(0));
    }

    #[test]
    fn test_clone_and_copy() {
        let original = ChildNumber::Normal(42);
        let cloned = original.clone();
        let copied = original;

        assert_eq!(original, cloned);
        assert_eq!(original, copied);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(ChildNumber::Normal(0));
        set.insert(ChildNumber::Normal(1));
        set.insert(ChildNumber::Hardened(0));

        assert!(set.contains(&ChildNumber::Normal(0)));
        assert!(set.contains(&ChildNumber::Hardened(0)));
        assert!(!set.contains(&ChildNumber::Normal(2)));
    }

    #[test]
    fn test_debug_format() {
        let normal = ChildNumber::Normal(42);
        let hardened = ChildNumber::Hardened(44);

        let normal_debug = format!("{:?}", normal);
        let hardened_debug = format!("{:?}", hardened);

        assert!(normal_debug.contains("Normal"));
        assert!(normal_debug.contains("42"));
        assert!(hardened_debug.contains("Hardened"));
        assert!(hardened_debug.contains("44"));
    }

    // ========================================================================
    // Conversion from u32 Tests (Task 27 - TDD)
    // ========================================================================

    #[test]
    fn test_from_u32_normal() {
        // Normal indices (0 to 2^31-1)
        let child_0 = ChildNumber::from_index(0);
        assert_eq!(child_0, ChildNumber::Normal(0));

        let child_1 = ChildNumber::from_index(1);
        assert_eq!(child_1, ChildNumber::Normal(1));

        let child_max = ChildNumber::from_index(ChildNumber::MAX_NORMAL_INDEX);
        assert_eq!(
            child_max,
            ChildNumber::Normal(ChildNumber::MAX_NORMAL_INDEX)
        );
    }

    #[test]
    fn test_from_u32_hardened() {
        // Hardened indices (2^31 to 2^32-1)
        let child_h0 = ChildNumber::from_index(ChildNumber::HARDENED_BIT);
        assert_eq!(child_h0, ChildNumber::Hardened(0));

        let child_h1 = ChildNumber::from_index(ChildNumber::HARDENED_BIT + 1);
        assert_eq!(child_h1, ChildNumber::Hardened(1));

        let child_h44 = ChildNumber::from_index(ChildNumber::HARDENED_BIT + 44);
        assert_eq!(child_h44, ChildNumber::Hardened(44));

        let child_max = ChildNumber::from_index(u32::MAX);
        assert_eq!(
            child_max,
            ChildNumber::Hardened(ChildNumber::MAX_NORMAL_INDEX)
        );
    }

    #[test]
    fn test_from_index_boundary() {
        // Test boundary between normal and hardened
        let last_normal = ChildNumber::from_index(0x7FFFFFFF);
        assert!(matches!(last_normal, ChildNumber::Normal(_)));

        let first_hardened = ChildNumber::from_index(0x80000000);
        assert!(matches!(first_hardened, ChildNumber::Hardened(_)));
    }

    // ========================================================================
    // Conversion to u32 Tests (Task 27 - TDD)
    // ========================================================================

    #[test]
    fn test_to_u32_normal() {
        assert_eq!(ChildNumber::Normal(0).to_index(), 0);
        assert_eq!(ChildNumber::Normal(1).to_index(), 1);
        assert_eq!(ChildNumber::Normal(42).to_index(), 42);
        assert_eq!(
            ChildNumber::Normal(ChildNumber::MAX_NORMAL_INDEX).to_index(),
            ChildNumber::MAX_NORMAL_INDEX
        );
    }

    #[test]
    fn test_to_u32_hardened() {
        assert_eq!(
            ChildNumber::Hardened(0).to_index(),
            ChildNumber::HARDENED_BIT
        );
        assert_eq!(
            ChildNumber::Hardened(1).to_index(),
            ChildNumber::HARDENED_BIT + 1
        );
        assert_eq!(
            ChildNumber::Hardened(44).to_index(),
            ChildNumber::HARDENED_BIT + 44
        );
        assert_eq!(
            ChildNumber::Hardened(ChildNumber::MAX_NORMAL_INDEX).to_index(),
            u32::MAX
        );
    }

    #[test]
    fn test_roundtrip_conversion() {
        // Normal values
        for i in [0, 1, 42, 100, ChildNumber::MAX_NORMAL_INDEX] {
            let child = ChildNumber::from_index(i);
            assert_eq!(child.to_index(), i);
        }

        // Hardened values
        for i in [
            ChildNumber::HARDENED_BIT,
            ChildNumber::HARDENED_BIT + 1,
            ChildNumber::HARDENED_BIT + 44,
            u32::MAX,
        ] {
            let child = ChildNumber::from_index(i);
            assert_eq!(child.to_index(), i);
        }
    }

    // ========================================================================
    // Query Methods Tests (Task 27 - TDD)
    // ========================================================================

    #[test]
    fn test_is_normal() {
        assert!(ChildNumber::Normal(0).is_normal());
        assert!(ChildNumber::Normal(42).is_normal());
        assert!(ChildNumber::Normal(ChildNumber::MAX_NORMAL_INDEX).is_normal());

        assert!(!ChildNumber::Hardened(0).is_normal());
        assert!(!ChildNumber::Hardened(44).is_normal());
    }

    #[test]
    fn test_is_hardened() {
        assert!(!ChildNumber::Normal(0).is_hardened());
        assert!(!ChildNumber::Normal(42).is_hardened());

        assert!(ChildNumber::Hardened(0).is_hardened());
        assert!(ChildNumber::Hardened(44).is_hardened());
        assert!(ChildNumber::Hardened(ChildNumber::MAX_NORMAL_INDEX).is_hardened());
    }

    #[test]
    fn test_is_normal_and_hardened_mutually_exclusive() {
        let normal = ChildNumber::Normal(42);
        assert!(normal.is_normal());
        assert!(!normal.is_hardened());

        let hardened = ChildNumber::Hardened(42);
        assert!(!hardened.is_normal());
        assert!(hardened.is_hardened());
    }

    // ========================================================================
    // Value Extraction Tests (Task 27 - TDD)
    // ========================================================================

    #[test]
    fn test_value_normal() {
        assert_eq!(ChildNumber::Normal(0).value(), 0);
        assert_eq!(ChildNumber::Normal(42).value(), 42);
        assert_eq!(
            ChildNumber::Normal(ChildNumber::MAX_NORMAL_INDEX).value(),
            ChildNumber::MAX_NORMAL_INDEX
        );
    }

    #[test]
    fn test_value_hardened() {
        // value() returns the stored value (without hardened bit)
        assert_eq!(ChildNumber::Hardened(0).value(), 0);
        assert_eq!(ChildNumber::Hardened(44).value(), 44);
        assert_eq!(
            ChildNumber::Hardened(ChildNumber::MAX_NORMAL_INDEX).value(),
            ChildNumber::MAX_NORMAL_INDEX
        );
    }

    #[test]
    fn test_value_vs_to_index() {
        // For Normal: value() == to_index()
        let normal = ChildNumber::Normal(42);
        assert_eq!(normal.value(), normal.to_index());

        // For Hardened: value() != to_index() (to_index adds HARDENED_BIT)
        let hardened = ChildNumber::Hardened(44);
        assert_eq!(hardened.value(), 44);
        assert_eq!(hardened.to_index(), ChildNumber::HARDENED_BIT + 44);
        assert_ne!(hardened.value(), hardened.to_index());
    }

    // ========================================================================
    // BIP-44 Common Values Tests (Task 27 - TDD)
    // ========================================================================

    #[test]
    fn test_bip44_purpose() {
        // BIP-44 uses purpose = 44'
        let purpose = ChildNumber::Hardened(44);
        assert_eq!(purpose.to_index(), 0x8000002C); // 2^31 + 44
        assert!(purpose.is_hardened());
    }

    #[test]
    fn test_bip44_bitcoin_coin_type() {
        // Bitcoin coin_type = 0'
        let coin_type = ChildNumber::Hardened(0);
        assert_eq!(coin_type.to_index(), 0x80000000); // 2^31 + 0
        assert!(coin_type.is_hardened());
    }

    #[test]
    fn test_bip44_first_account() {
        // First account = 0'
        let account = ChildNumber::Hardened(0);
        assert_eq!(account.value(), 0);
        assert!(account.is_hardened());
    }

    #[test]
    fn test_bip44_external_chain() {
        // External chain (receiving addresses) = 0 (normal)
        let chain = ChildNumber::Normal(0);
        assert_eq!(chain.to_index(), 0);
        assert!(chain.is_normal());
    }

    #[test]
    fn test_bip44_internal_chain() {
        // Internal chain (change addresses) = 1 (normal)
        let chain = ChildNumber::Normal(1);
        assert_eq!(chain.to_index(), 1);
        assert!(chain.is_normal());
    }
}
