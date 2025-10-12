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
/// ```rust,ignore
/// use bip32::ChildNumber;
///
/// // Normal child numbers (for address generation)
/// let normal_0 = ChildNumber::Normal(0);
/// let normal_5 = ChildNumber::Normal(5);
///
/// // Hardened child numbers (for account/coin levels)
/// let hardened_0 = ChildNumber::Hardened(0);   // Often written as 0'
/// let hardened_44 = ChildNumber::Hardened(44); // Often written as 44'
///
/// // BIP-44 path components
/// let purpose = ChildNumber::Hardened(44);     // m/44'
/// let coin_type = ChildNumber::Hardened(0);    // /0' (Bitcoin)
/// let account = ChildNumber::Hardened(0);      // /0' (first account)
/// let change = ChildNumber::Normal(0);         // /0 (external chain)
/// let index = ChildNumber::Normal(0);          // /0 (first address)
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
}
