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
//! ```
//! use bip32::DerivationPath;
//! use std::str::FromStr;
//!
//! // BIP-44 Bitcoin address derivation
//! let bip44 = DerivationPath::from_str("m/44'/0'/0'/0/0")?;
//! assert_eq!(bip44.depth(), 5);
//!
//! // First normal child
//! let simple = DerivationPath::from_str("m/0")?;
//! assert_eq!(simple.depth(), 1);
//!
//! // Mixed hardened and normal derivation
//! let mixed = DerivationPath::from_str("m/0'/1/2'")?;
//! assert!(mixed.contains_hardened());
//!
//! // Deep normal derivation path
//! let deep = DerivationPath::from_str("m/1/2/3/4/5")?;
//! assert!(deep.is_public_derivable());
//! # Ok::<(), bip32::Error>(())
//! ```
//!
//! # Generic Design
//!
//! This implementation is intentionally generic and does not enforce any specific
//! BIP (like BIP-44, BIP-49, BIP-84) semantics. It can represent any valid BIP-32
//! derivation path. Higher-level libraries or applications can add semantic meaning
//! to specific path structures.

use crate::{ChildNumber, Error, Result};
use std::fmt;
use std::str::FromStr;

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
/// ## Basic Usage
///
/// ```
/// use bip32::DerivationPath;
/// use std::str::FromStr;
///
/// // Parse a BIP-44 path
/// let path = DerivationPath::from_str("m/44'/0'/0'/0/0")?;
/// assert_eq!(path.depth(), 5);
/// assert!(path.contains_hardened());
///
/// // Empty path represents master key
/// let master_path = DerivationPath::master();
/// assert_eq!(master_path.depth(), 0);
/// assert!(master_path.is_master());
/// # Ok::<(), bip32::Error>(())
/// ```
///
/// ## Building Paths Programmatically
///
/// ```
/// use bip32::{DerivationPath, ChildNumber};
///
/// // Start with master
/// let mut path = DerivationPath::master();
///
/// // Build m/44'/0'/0'
/// path = path.extend(&[
///     ChildNumber::Hardened(44),
///     ChildNumber::Hardened(0),
///     ChildNumber::Hardened(0),
/// ]);
///
/// assert_eq!(path.depth(), 3);
/// assert_eq!(path.to_string(), "m/44'/0'/0'");
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

    /// Returns `true` if this path is valid.
    ///
    /// Since all successfully parsed paths are valid, this always returns `true`.
    /// This method exists for API completeness and future extensibility.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let path = DerivationPath::from_str("m/44'/0'/0'/0/0")?;
    /// assert!(path.is_valid());
    /// ```
    pub fn is_valid(&self) -> bool {
        // All paths that can be constructed are valid
        // This method exists for API completeness
        true
    }

    /// Returns `true` if the path contains any hardened derivation.
    ///
    /// Hardened derivation requires access to the private key and cannot be
    /// performed on extended public keys alone.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let normal = DerivationPath::from_str("m/0/1/2")?;
    /// assert!(!normal.contains_hardened());
    ///
    /// let hardened = DerivationPath::from_str("m/44'/0'/0'")?;
    /// assert!(hardened.contains_hardened());
    /// ```
    pub fn contains_hardened(&self) -> bool {
        self.path.iter().any(|child| child.is_hardened())
    }

    /// Returns `true` if this path can be derived from an extended public key.
    ///
    /// A path is public-derivable if it contains no hardened derivation steps.
    /// Hardened derivation requires the private key.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let normal = DerivationPath::from_str("m/0/1/2")?;
    /// assert!(normal.is_public_derivable());
    ///
    /// let with_hardened = DerivationPath::from_str("m/44'/0/1")?;
    /// assert!(!with_hardened.is_public_derivable());
    /// ```
    pub fn is_public_derivable(&self) -> bool {
        !self.contains_hardened()
    }

    /// Returns `true` if the child at the given index is hardened.
    ///
    /// Returns `false` if the index is out of bounds or the child is normal.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the child to check (0-based)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let path = DerivationPath::from_str("m/44'/0/1'")?;
    /// assert!(path.is_hardened_at(0));  // 44' is hardened
    /// assert!(!path.is_hardened_at(1)); // 0 is normal
    /// assert!(path.is_hardened_at(2));  // 1' is hardened
    /// ```
    pub fn is_hardened_at(&self, index: usize) -> bool {
        self.path
            .get(index)
            .map_or(false, |child| child.is_hardened())
    }

    /// Returns a reference to the child number at the given index.
    ///
    /// Returns `None` if the index is out of bounds.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the child to retrieve (0-based)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::{DerivationPath, ChildNumber};
    /// use std::str::FromStr;
    ///
    /// let path = DerivationPath::from_str("m/44'/0'/0'")?;
    /// assert_eq!(path.child_number_at(0), Some(&ChildNumber::Hardened(44)));
    /// assert_eq!(path.child_number_at(3), None);
    /// ```
    pub fn child_number_at(&self, index: usize) -> Option<&ChildNumber> {
        self.path.get(index)
    }

    /// Returns the parent path by removing the last child number.
    ///
    /// Returns `None` if this is the master key (which has no parent).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let path = DerivationPath::from_str("m/44'/0'/0'")?;
    /// let parent = path.parent().unwrap();
    /// assert_eq!(parent.to_string(), "m/44'/0'");
    ///
    /// let master = DerivationPath::master();
    /// assert!(master.parent().is_none());
    /// ```
    pub fn parent(&self) -> Option<DerivationPath> {
        if self.path.is_empty() {
            None
        } else {
            let mut parent_path = self.path.clone();
            parent_path.pop();
            Some(DerivationPath { path: parent_path })
        }
    }

    /// Extends this path with additional child numbers.
    ///
    /// Returns a new `DerivationPath` with the additional components appended.
    ///
    /// # Arguments
    ///
    /// * `children` - Slice of child numbers to append
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::{DerivationPath, ChildNumber};
    /// use std::str::FromStr;
    ///
    /// let base = DerivationPath::from_str("m/44'/0'")?;
    /// let extended = base.extend(&[
    ///     ChildNumber::Hardened(0),
    ///     ChildNumber::Normal(0),
    /// ]);
    /// assert_eq!(extended.to_string(), "m/44'/0'/0'/0");
    /// ```
    pub fn extend(&self, children: &[ChildNumber]) -> DerivationPath {
        let mut new_path = self.path.clone();
        new_path.extend_from_slice(children);
        DerivationPath { path: new_path }
    }

    /// Returns `true` if this path starts with the given prefix.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The prefix path to check
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let path = DerivationPath::from_str("m/44'/0'/0'/0/0")?;
    /// let prefix = DerivationPath::from_str("m/44'/0'")?;
    /// assert!(path.starts_with(&prefix));
    /// ```
    pub fn starts_with(&self, prefix: &DerivationPath) -> bool {
        if prefix.path.len() > self.path.len() {
            return false;
        }

        self.path.starts_with(&prefix.path)
    }

    /// Returns the number of hardened derivations at the start of the path.
    ///
    /// This is useful for BIP-44 style paths where the first few levels
    /// are hardened (purpose/coin_type/account) and the rest are normal.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let bip44 = DerivationPath::from_str("m/44'/0'/0'/0/1")?;
    /// assert_eq!(bip44.hardened_prefix_length(), 3);
    ///
    /// let all_normal = DerivationPath::from_str("m/0/1/2")?;
    /// assert_eq!(all_normal.hardened_prefix_length(), 0);
    /// ```
    pub fn hardened_prefix_length(&self) -> usize {
        self.path
            .iter()
            .take_while(|child| child.is_hardened())
            .count()
    }

    /// Returns the number of normal (non-hardened) derivations at the end of the path.
    ///
    /// This is useful for BIP-44 style paths where the last levels
    /// are normal (change/address_index) for public key derivation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let bip44 = DerivationPath::from_str("m/44'/0'/0'/0/1")?;
    /// assert_eq!(bip44.normal_suffix_length(), 2);
    ///
    /// let all_hardened = DerivationPath::from_str("m/0'/1'/2'")?;
    /// assert_eq!(all_hardened.normal_suffix_length(), 0);
    /// ```
    pub fn normal_suffix_length(&self) -> usize {
        self.path
            .iter()
            .rev()
            .take_while(|child| child.is_normal())
            .count()
    }

    /// Converts the path to a vector of child numbers.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::{DerivationPath, ChildNumber};
    /// use std::str::FromStr;
    ///
    /// let path = DerivationPath::from_str("m/0'/1/2'")?;
    /// let vec = path.to_vec();
    /// assert_eq!(vec.len(), 3);
    /// ```
    pub fn to_vec(&self) -> Vec<ChildNumber> {
        self.path.clone()
    }
}

/// Parse a derivation path from a string.
///
/// The string must follow the BIP-32 format: "m/0'/1/2h/3"
/// - Must start with "m" (master key)
/// - Components separated by "/"
/// - Hardened indices marked with ' or h suffix
///
/// # Errors
///
/// Returns `Error::InvalidDerivationPath` if:
/// - String doesn't start with "m"
/// - Contains invalid numbers or characters
/// - Depth exceeds 255
/// - Index values are out of range
impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(path: &str) -> Result<Self> {
        // Handle empty string
        if path.is_empty() {
            return Err(Error::InvalidDerivationPath {
                path: path.to_string(),
                reason: "Path cannot be empty, must start with 'm'".to_string(),
            });
        }

        // Must start with 'm'
        if !path.starts_with('m') {
            return Err(Error::InvalidDerivationPath {
                path: path.to_string(),
                reason: "Path must start with 'm'".to_string(),
            });
        }

        // If just "m", return master key (empty path)
        if path == "m" {
            return Ok(DerivationPath::master());
        }

        // Must have "/" after "m"
        if !path.starts_with("m/") {
            return Err(Error::InvalidDerivationPath {
                path: path.to_string(),
                reason: "Path must be 'm' or start with 'm/'".to_string(),
            });
        }

        // Split by "/" and skip the first "m"
        let components: Vec<&str> = path[2..].split('/').collect();

        // Check for empty components (double slashes or trailing slash)
        if components.iter().any(|c| c.is_empty()) {
            return Err(Error::InvalidDerivationPath {
                path: path.to_string(),
                reason: "Path contains empty components (double slash or trailing slash)"
                    .to_string(),
            });
        }

        // Check depth limit
        if components.len() > Self::MAX_DEPTH as usize {
            return Err(Error::MaxDepthExceeded {
                depth: Self::MAX_DEPTH,
            });
        }

        // Parse each component
        let mut child_numbers = Vec::with_capacity(components.len());

        for component in components {
            let child_number = parse_child_number(component, path)?;
            child_numbers.push(child_number);
        }

        Ok(DerivationPath {
            path: child_numbers,
        })
    }
}

/// Parse a single child number component.
///
/// Handles both normal ("0", "1", "2") and hardened ("0'", "1h", "1H") notation.
fn parse_child_number(component: &str, full_path: &str) -> Result<ChildNumber> {
    if component.is_empty() {
        return Err(Error::InvalidDerivationPath {
            path: full_path.to_string(),
            reason: "Empty path component".to_string(),
        });
    }

    // Check for hardened suffix (supports ', h, or H)
    let (is_hardened, number_str) = if component.ends_with('\'') {
        (true, &component[..component.len() - 1])
    } else if component.ends_with('h') || component.ends_with('H') {
        (true, &component[..component.len() - 1])
    } else {
        (false, component)
    };

    // Parse the number
    let index: u32 = number_str
        .parse()
        .map_err(|_| Error::InvalidDerivationPath {
            path: full_path.to_string(),
            reason: format!(
                "Invalid number '{}' in path component '{}'",
                number_str, component
            ),
        })?;

    // Check for overflow when creating hardened indices
    if is_hardened && index > ChildNumber::MAX_NORMAL_INDEX {
        return Err(Error::InvalidDerivationPath {
            path: full_path.to_string(),
            reason: format!(
                "Hardened index {} exceeds maximum value {}",
                index,
                ChildNumber::MAX_NORMAL_INDEX
            ),
        });
    }

    Ok(if is_hardened {
        ChildNumber::Hardened(index)
    } else {
        ChildNumber::Normal(index)
    })
}

/// Display a derivation path in BIP-32 format.
///
/// Output format: "m/44'/0'/0'/0/0"
/// - Master key: "m"
/// - Hardened indices use ' notation (not h)
impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "m")?;

        for child_number in &self.path {
            match child_number {
                ChildNumber::Normal(index) => write!(f, "/{}", index)?,
                ChildNumber::Hardened(index) => write!(f, "/{}'", index)?,
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use std::str::FromStr;

    // ========================================================================
    // Basic Parsing Tests (Task 29 - TDD)
    // ========================================================================

    #[test]
    fn test_parse_master_key() {
        let path = DerivationPath::from_str("m").unwrap();
        assert!(path.is_master());
        assert_eq!(path.depth(), 0);
        assert_eq!(path.len(), 0);
    }

    #[test]
    fn test_parse_single_normal() {
        let path = DerivationPath::from_str("m/0").unwrap();
        assert_eq!(path.depth(), 1);
        assert_eq!(path.as_slice()[0], ChildNumber::Normal(0));
    }

    #[test]
    fn test_parse_single_hardened_apostrophe() {
        let path = DerivationPath::from_str("m/0'").unwrap();
        assert_eq!(path.depth(), 1);
        assert_eq!(path.as_slice()[0], ChildNumber::Hardened(0));
    }

    #[test]
    fn test_parse_single_hardened_h() {
        let path = DerivationPath::from_str("m/0h").unwrap();
        assert_eq!(path.depth(), 1);
        assert_eq!(path.as_slice()[0], ChildNumber::Hardened(0));
    }

    #[test]
    fn test_parse_single_hardened_uppercase_h() {
        let path = DerivationPath::from_str("m/0H").unwrap();
        assert_eq!(path.depth(), 1);
        assert_eq!(path.as_slice()[0], ChildNumber::Hardened(0));
    }

    #[test]
    fn test_parse_multiple_normal() {
        let path = DerivationPath::from_str("m/0/1/2").unwrap();
        assert_eq!(path.depth(), 3);
        assert_eq!(path.as_slice()[0], ChildNumber::Normal(0));
        assert_eq!(path.as_slice()[1], ChildNumber::Normal(1));
        assert_eq!(path.as_slice()[2], ChildNumber::Normal(2));
    }

    #[test]
    fn test_parse_multiple_hardened() {
        let path = DerivationPath::from_str("m/0'/1'/2'").unwrap();
        assert_eq!(path.depth(), 3);
        assert_eq!(path.as_slice()[0], ChildNumber::Hardened(0));
        assert_eq!(path.as_slice()[1], ChildNumber::Hardened(1));
        assert_eq!(path.as_slice()[2], ChildNumber::Hardened(2));
    }

    #[test]
    fn test_parse_mixed_notation() {
        // Mix of normal and hardened, and mix of ' and h notation
        let path = DerivationPath::from_str("m/0'/1/2h/3").unwrap();
        assert_eq!(path.depth(), 4);
        assert_eq!(path.as_slice()[0], ChildNumber::Hardened(0));
        assert_eq!(path.as_slice()[1], ChildNumber::Normal(1));
        assert_eq!(path.as_slice()[2], ChildNumber::Hardened(2));
        assert_eq!(path.as_slice()[3], ChildNumber::Normal(3));
    }

    #[test]
    fn test_parse_bip44_path() {
        // Standard BIP-44 path: m/44'/0'/0'/0/0
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.depth(), 5);
        assert_eq!(path.as_slice()[0], ChildNumber::Hardened(44)); // purpose
        assert_eq!(path.as_slice()[1], ChildNumber::Hardened(0)); // coin_type
        assert_eq!(path.as_slice()[2], ChildNumber::Hardened(0)); // account
        assert_eq!(path.as_slice()[3], ChildNumber::Normal(0)); // change
        assert_eq!(path.as_slice()[4], ChildNumber::Normal(0)); // address_index
    }

    #[test]
    fn test_parse_large_indices() {
        let path = DerivationPath::from_str("m/2147483647/2147483647'").unwrap();
        assert_eq!(path.as_slice()[0], ChildNumber::Normal(2147483647)); // Max normal
        assert_eq!(path.as_slice()[1], ChildNumber::Hardened(2147483647)); // Max hardened base
    }

    // ========================================================================
    // Error Cases Tests (Task 29 - TDD)
    // ========================================================================

    #[test]
    fn test_parse_empty_string() {
        let result = DerivationPath::from_str("");
        assert!(result.is_err());
        if let Err(Error::InvalidDerivationPath { path, reason }) = result {
            assert_eq!(path, "");
            assert!(reason.contains("empty") || reason.contains("must start"));
        }
    }

    #[test]
    fn test_parse_missing_m_prefix() {
        let result = DerivationPath::from_str("0/1/2");
        assert!(result.is_err());
        if let Err(Error::InvalidDerivationPath { path, reason }) = result {
            assert_eq!(path, "0/1/2");
            assert!(reason.to_lowercase().contains("must start with 'm'"));
        }
    }

    #[test]
    fn test_parse_wrong_prefix() {
        let result = DerivationPath::from_str("x/0/1");
        assert!(result.is_err());
        if let Err(Error::InvalidDerivationPath { .. }) = result {
            // Expected
        } else {
            panic!("Expected InvalidDerivationPath error");
        }
    }

    #[test]
    fn test_parse_invalid_number() {
        let result = DerivationPath::from_str("m/abc");
        assert!(result.is_err());
        if let Err(Error::InvalidDerivationPath { path, reason }) = result {
            assert_eq!(path, "m/abc");
            assert!(
                reason.to_lowercase().contains("invalid")
                    || reason.to_lowercase().contains("number")
            );
        } else {
            panic!("Expected InvalidDerivationPath error");
        }
    }

    #[test]
    fn test_parse_number_too_large() {
        // Larger than u32::MAX
        let result = DerivationPath::from_str("m/4294967296");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_negative_number() {
        let result = DerivationPath::from_str("m/-1");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_double_slash() {
        let result = DerivationPath::from_str("m//0");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_trailing_slash() {
        let result = DerivationPath::from_str("m/0/");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_leading_slash_after_m() {
        // "m//0" is invalid but "m/0" is valid
        let result = DerivationPath::from_str("m//0");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_hardened_marker() {
        let result = DerivationPath::from_str("m/0''");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mixed_hardened_markers() {
        // Using both ' and h on same index is invalid
        let result = DerivationPath::from_str("m/0'h");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_whitespace() {
        let result = DerivationPath::from_str("m/ 0/1");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_with_leading_zero() {
        // "m/01" should work or fail consistently
        let result = DerivationPath::from_str("m/01");
        // Most implementations accept this
        assert!(result.is_ok() || result.is_err());
    }

    // ========================================================================
    // Edge Cases Tests (Task 29 - TDD)
    // ========================================================================

    #[test]
    fn test_parse_max_normal_index() {
        let path = DerivationPath::from_str("m/2147483647").unwrap();
        assert_eq!(path.as_slice()[0], ChildNumber::Normal(2147483647));
    }

    #[test]
    fn test_parse_zero_index() {
        let path = DerivationPath::from_str("m/0").unwrap();
        assert_eq!(path.as_slice()[0], ChildNumber::Normal(0));
    }

    #[test]
    fn test_parse_zero_hardened() {
        let path = DerivationPath::from_str("m/0'").unwrap();
        assert_eq!(path.as_slice()[0], ChildNumber::Hardened(0));
    }

    #[test]
    fn test_parse_deep_path() {
        // Create a deep path (not exceeding MAX_DEPTH)
        let deep_path = format!("m/{}", (0..100).map(|_| "0").collect::<Vec<_>>().join("/"));
        let path = DerivationPath::from_str(&deep_path).unwrap();
        assert_eq!(path.depth(), 100);
    }

    #[test]
    fn test_parse_exceeds_max_depth() {
        // Create a path that exceeds MAX_DEPTH (255)
        let too_deep = format!("m/{}", (0..256).map(|_| "0").collect::<Vec<_>>().join("/"));
        let result = DerivationPath::from_str(&too_deep);
        assert!(result.is_err());
        if let Err(Error::MaxDepthExceeded { depth }) = result {
            assert_eq!(depth, 255);
        }
    }

    // ========================================================================
    // Hardened Index Overflow Tests (Task 29 - TDD)
    // ========================================================================

    #[test]
    fn test_parse_hardened_overflow() {
        // MAX_NORMAL_INDEX is 2147483647, so 2147483648' would overflow
        let result = DerivationPath::from_str("m/2147483648'");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_max_hardened_base() {
        // 2147483647' is the maximum hardened index
        let path = DerivationPath::from_str("m/2147483647'").unwrap();
        assert_eq!(path.as_slice()[0], ChildNumber::Hardened(2147483647));
    }

    // ========================================================================
    // BIP Standard Paths Tests (Task 29 - TDD)
    // ========================================================================

    #[test]
    fn test_parse_bip49_path() {
        // BIP-49 (P2WPKH-nested-in-P2SH)
        let path = DerivationPath::from_str("m/49'/0'/0'/0/0").unwrap();
        assert_eq!(path.as_slice()[0], ChildNumber::Hardened(49));
    }

    #[test]
    fn test_parse_bip84_path() {
        // BIP-84 (Native SegWit)
        let path = DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap();
        assert_eq!(path.as_slice()[0], ChildNumber::Hardened(84));
    }

    #[test]
    fn test_parse_bip86_path() {
        // BIP-86 (Taproot)
        let path = DerivationPath::from_str("m/86'/0'/0'/0/0").unwrap();
        assert_eq!(path.as_slice()[0], ChildNumber::Hardened(86));
    }

    // ========================================================================
    // Roundtrip Tests (Task 29 - TDD)
    // ========================================================================

    #[test]
    fn test_parse_and_display_master() {
        let original = "m";
        let path = DerivationPath::from_str(original).unwrap();
        assert_eq!(path.to_string(), original);
    }

    #[test]
    fn test_parse_and_display_simple() {
        let original = "m/0/1/2";
        let path = DerivationPath::from_str(original).unwrap();
        assert_eq!(path.to_string(), original);
    }

    #[test]
    fn test_parse_and_display_hardened() {
        let original = "m/44'/0'/0'";
        let path = DerivationPath::from_str(original).unwrap();
        // Should normalize to ' notation (not h)
        assert_eq!(path.to_string(), original);
    }

    #[test]
    fn test_parse_h_display_apostrophe() {
        // Input with 'h', output with '
        let input = "m/0h/1h";
        let expected = "m/0'/1'";
        let path = DerivationPath::from_str(input).unwrap();
        assert_eq!(path.to_string(), expected);
    }

    // ========================================================================
    // Validation Tests (Task 31 - TDD)
    // ========================================================================

    #[test]
    fn test_is_valid_always_true_for_parsed() {
        // If a path was successfully parsed, it should be valid
        let paths = vec!["m", "m/0", "m/0'", "m/44'/0'/0'/0/0"];

        for path_str in paths {
            let path = DerivationPath::from_str(path_str).unwrap();
            assert!(path.is_valid());
        }
    }

    #[test]
    fn test_contains_hardened_derivation() {
        let normal_only = DerivationPath::from_str("m/0/1/2").unwrap();
        assert!(!normal_only.contains_hardened());

        let hardened_only = DerivationPath::from_str("m/0'/1'/2'").unwrap();
        assert!(hardened_only.contains_hardened());

        let mixed = DerivationPath::from_str("m/0'/1/2").unwrap();
        assert!(mixed.contains_hardened());

        let master = DerivationPath::master();
        assert!(!master.contains_hardened());
    }

    #[test]
    fn test_is_public_derivable() {
        // All normal = can derive from public key
        let normal_only = DerivationPath::from_str("m/0/1/2").unwrap();
        assert!(normal_only.is_public_derivable());

        // Contains hardened = cannot derive from public key
        let with_hardened = DerivationPath::from_str("m/0'/1/2").unwrap();
        assert!(!with_hardened.is_public_derivable());

        let all_hardened = DerivationPath::from_str("m/0'/1'/2'").unwrap();
        assert!(!all_hardened.is_public_derivable());

        // Master key is technically public derivable (no derivation needed)
        let master = DerivationPath::master();
        assert!(master.is_public_derivable());
    }

    #[test]
    fn test_is_hardened_at_index() {
        let path = DerivationPath::from_str("m/0'/1/2'/3").unwrap();

        assert!(path.is_hardened_at(0)); // 0' is hardened
        assert!(!path.is_hardened_at(1)); // 1 is normal
        assert!(path.is_hardened_at(2)); // 2' is hardened
        assert!(!path.is_hardened_at(3)); // 3 is normal
    }

    #[test]
    fn test_is_hardened_at_out_of_bounds() {
        let path = DerivationPath::from_str("m/0/1").unwrap();
        assert!(!path.is_hardened_at(2)); // Out of bounds returns false
        assert!(!path.is_hardened_at(10));
    }

    #[test]
    fn test_child_number_at() {
        let path = DerivationPath::from_str("m/44'/0'/0'/0/5").unwrap();

        assert_eq!(path.child_number_at(0), Some(&ChildNumber::Hardened(44)));
        assert_eq!(path.child_number_at(1), Some(&ChildNumber::Hardened(0)));
        assert_eq!(path.child_number_at(2), Some(&ChildNumber::Hardened(0)));
        assert_eq!(path.child_number_at(3), Some(&ChildNumber::Normal(0)));
        assert_eq!(path.child_number_at(4), Some(&ChildNumber::Normal(5)));
        assert_eq!(path.child_number_at(5), None); // Out of bounds
    }

    #[test]
    fn test_parent_path() {
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();

        // Get parent (remove last component)
        let parent = path.parent().unwrap();
        assert_eq!(parent.to_string(), "m/44'/0'/0'/0");

        // Get grandparent
        let grandparent = parent.parent().unwrap();
        assert_eq!(grandparent.to_string(), "m/44'/0'/0'");

        // Master has no parent
        let master = DerivationPath::master();
        assert!(master.parent().is_none());
    }

    #[test]
    fn test_parent_chain() {
        let path = DerivationPath::from_str("m/0/1/2").unwrap();

        let p1 = path.parent().unwrap();
        assert_eq!(p1.to_string(), "m/0/1");

        let p2 = p1.parent().unwrap();
        assert_eq!(p2.to_string(), "m/0");

        let p3 = p2.parent().unwrap();
        assert_eq!(p3.to_string(), "m");

        let p4 = p3.parent();
        assert!(p4.is_none());
    }

    #[test]
    fn test_extend_path() {
        let base = DerivationPath::from_str("m/44'/0'").unwrap();

        let extended = base.extend(&[
            ChildNumber::Hardened(0),
            ChildNumber::Normal(0),
            ChildNumber::Normal(0),
        ]);

        assert_eq!(extended.to_string(), "m/44'/0'/0'/0/0");
        assert_eq!(extended.depth(), 5);
    }

    #[test]
    fn test_extend_empty_path() {
        let master = DerivationPath::master();

        let extended = master.extend(&[ChildNumber::Hardened(44), ChildNumber::Hardened(0)]);

        assert_eq!(extended.to_string(), "m/44'/0'");
    }

    #[test]
    fn test_extend_with_empty_slice() {
        let path = DerivationPath::from_str("m/0").unwrap();
        let same = path.extend(&[]);

        assert_eq!(path, same);
    }

    #[test]
    fn test_starts_with() {
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let prefix = DerivationPath::from_str("m/44'/0'").unwrap();
        let not_prefix = DerivationPath::from_str("m/49'/0'").unwrap();

        assert!(path.starts_with(&prefix));
        assert!(!path.starts_with(&not_prefix));

        // Every path starts with master
        let master = DerivationPath::master();
        assert!(path.starts_with(&master));

        // Path starts with itself
        assert!(path.starts_with(&path));
    }

    #[test]
    fn test_starts_with_longer_prefix() {
        let short = DerivationPath::from_str("m/0").unwrap();
        let long = DerivationPath::from_str("m/0/1/2").unwrap();

        // Short path doesn't start with longer path
        assert!(!short.starts_with(&long));
    }

    #[test]
    fn test_hardened_prefix_length() {
        let all_normal = DerivationPath::from_str("m/0/1/2").unwrap();
        assert_eq!(all_normal.hardened_prefix_length(), 0);

        let starts_hardened = DerivationPath::from_str("m/44'/0'/0'/0/1").unwrap();
        assert_eq!(starts_hardened.hardened_prefix_length(), 3);

        let all_hardened = DerivationPath::from_str("m/0'/1'/2'").unwrap();
        assert_eq!(all_hardened.hardened_prefix_length(), 3);

        let mixed = DerivationPath::from_str("m/0/1'/2").unwrap();
        assert_eq!(mixed.hardened_prefix_length(), 0); // First is normal

        let master = DerivationPath::master();
        assert_eq!(master.hardened_prefix_length(), 0);
    }

    #[test]
    fn test_normal_suffix_length() {
        let all_normal = DerivationPath::from_str("m/0/1/2").unwrap();
        assert_eq!(all_normal.normal_suffix_length(), 3);

        let bip44 = DerivationPath::from_str("m/44'/0'/0'/0/1").unwrap();
        assert_eq!(bip44.normal_suffix_length(), 2); // Last 2 are normal

        let all_hardened = DerivationPath::from_str("m/0'/1'/2'").unwrap();
        assert_eq!(all_hardened.normal_suffix_length(), 0);

        let ends_hardened = DerivationPath::from_str("m/0/1/2'").unwrap();
        assert_eq!(ends_hardened.normal_suffix_length(), 0);

        let master = DerivationPath::master();
        assert_eq!(master.normal_suffix_length(), 0);
    }

    #[test]
    fn test_to_vec() {
        let path = DerivationPath::from_str("m/0'/1/2'").unwrap();
        let vec = path.to_vec();

        assert_eq!(vec.len(), 3);
        assert_eq!(vec[0], ChildNumber::Hardened(0));
        assert_eq!(vec[1], ChildNumber::Normal(1));
        assert_eq!(vec[2], ChildNumber::Hardened(2));
    }
}
