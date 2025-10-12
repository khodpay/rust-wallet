//! BIP-32 derivation path implementation.
//!
//! This module provides the `DerivationPath` struct which represents a path in the
//! BIP-32 hierarchical deterministic key tree. Derivation paths specify how to derive
//! child keys from a master key by following a sequence of child indices.
//!
//! # Path Format
//!
//! Derivation paths follow the BIP-32 notation:
//! - `m` represents the master key
//! - `/` separates path components
//! - Numbers represent child indices
//! - `'` or `h` suffix indicates hardened derivation
//!
//! # Examples
//!
//! ```text
//! m/44'/0'/0'/0/0    - BIP-44 Bitcoin address derivation
//! m/0                - First normal child
//! m/0'/1/2'          - Mixed hardened and normal derivation
//! m/1/2/3/4/5        - Deep normal derivation path
//! ```
//!
//! # Generic Design
//!
//! This implementation is intentionally generic and does not enforce any specific
//! BIP (like BIP-44, BIP-49, BIP-84) semantics. It can represent any valid BIP-32
//! derivation path. Higher-level libraries or applications can add semantic meaning
//! to specific path structures.

use crate::ChildNumber;

/// A BIP-32 derivation path.
///
/// Represents a sequence of child numbers that specify how to derive a key from
/// the master key by following the hierarchical tree structure defined in BIP-32.
///
/// # Structure
///
/// The path is stored as a vector of `ChildNumber` components, where each component
/// can be either normal (non-hardened) or hardened.
///
/// # Depth
///
/// - Master key (m): depth 0, no path components
/// - First child (m/0): depth 1, one path component
/// - Second level (m/0/1): depth 2, two path components
/// - Maximum depth: 255 (BIP-32 limitation)
///
/// # Examples
///
/// ```rust,ignore
/// use bip32::DerivationPath;
///
/// // Parse a BIP-44 path (future functionality)
/// let path = DerivationPath::from_str("m/44'/0'/0'/0/0")?;
/// assert_eq!(path.depth(), 5);
///
/// // Empty path represents master key
/// let master_path = DerivationPath::master();
/// assert_eq!(master_path.depth(), 0);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath {
    /// The sequence of child numbers from master key to the target key.
    ///
    /// An empty vector represents the master key itself (m).
    /// Each element represents one level of derivation.
    path: Vec<ChildNumber>,
}

impl DerivationPath {
    /// Maximum depth allowed by BIP-32 specification.
    ///
    /// This matches the maximum depth enforced by `ExtendedPrivateKey` and
    /// `ExtendedPublicKey` structures.
    pub const MAX_DEPTH: u8 = 255;

    /// Creates a new derivation path from a vector of child numbers.
    ///
    /// # Arguments
    ///
    /// * `path` - Vector of child numbers representing the derivation path
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::{DerivationPath, ChildNumber};
    ///
    /// let path = DerivationPath::new(vec![
    ///     ChildNumber::Hardened(44),
    ///     ChildNumber::Hardened(0),
    ///     ChildNumber::Normal(0),
    /// ]);
    /// ```
    pub fn new(path: Vec<ChildNumber>) -> Self {
        DerivationPath { path }
    }

    /// Creates an empty derivation path representing the master key.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    ///
    /// let master = DerivationPath::master();
    /// assert_eq!(master.depth(), 0);
    /// assert!(master.is_master());
    /// ```
    pub fn master() -> Self {
        DerivationPath { path: Vec::new() }
    }

    /// Returns the depth of this derivation path.
    ///
    /// The depth is the number of derivation steps from the master key.
    /// - Master key (m): depth 0
    /// - m/0: depth 1
    /// - m/0/1: depth 2
    /// - etc.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::{DerivationPath, ChildNumber};
    ///
    /// let path = DerivationPath::new(vec![
    ///     ChildNumber::Normal(0),
    ///     ChildNumber::Normal(1),
    /// ]);
    /// assert_eq!(path.depth(), 2);
    /// ```
    pub fn depth(&self) -> u8 {
        self.path.len() as u8
    }

    /// Returns `true` if this path represents the master key (empty path).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    ///
    /// let master = DerivationPath::master();
    /// assert!(master.is_master());
    ///
    /// let child = DerivationPath::new(vec![ChildNumber::Normal(0)]);
    /// assert!(!child.is_master());
    /// ```
    pub fn is_master(&self) -> bool {
        self.path.is_empty()
    }

    /// Returns a slice of the child numbers in this path.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::{DerivationPath, ChildNumber};
    ///
    /// let path = DerivationPath::new(vec![
    ///     ChildNumber::Hardened(44),
    ///     ChildNumber::Normal(0),
    /// ]);
    ///
    /// let components = path.as_slice();
    /// assert_eq!(components.len(), 2);
    /// ```
    pub fn as_slice(&self) -> &[ChildNumber] {
        &self.path
    }

    /// Returns an iterator over the child numbers in this path.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::{DerivationPath, ChildNumber};
    ///
    /// let path = DerivationPath::new(vec![
    ///     ChildNumber::Normal(0),
    ///     ChildNumber::Normal(1),
    /// ]);
    ///
    /// for child_num in path.iter() {
    ///     println!("{:?}", child_num);
    /// }
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = &ChildNumber> {
        self.path.iter()
    }

    /// Returns the number of child numbers in this path.
    ///
    /// This is equivalent to `depth()` but returns `usize` instead of `u8`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    ///
    /// let path = DerivationPath::new(vec![
    ///     ChildNumber::Normal(0),
    ///     ChildNumber::Normal(1),
    ///     ChildNumber::Normal(2),
    /// ]);
    /// assert_eq!(path.len(), 3);
    /// ```
    pub fn len(&self) -> usize {
        self.path.len()
    }

    /// Returns `true` if the path is empty (represents master key).
    ///
    /// This is equivalent to `is_master()`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    ///
    /// let path = DerivationPath::master();
    /// assert!(path.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.path.is_empty()
    }
}
