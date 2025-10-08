//! Extended private key implementation for BIP32 hierarchical deterministic wallets.
//!
//! This module provides the core ExtendedPrivateKey type which combines a private key
//! with metadata necessary for hierarchical key derivation according to BIP-32.

use crate::{ChainCode, Network, PrivateKey};

/// An extended private key for BIP32 hierarchical deterministic wallets.
///
/// Extended keys combine a private key with additional metadata required for
/// hierarchical key derivation. This allows deriving child keys deterministically
/// from a parent key while maintaining the tree structure.
///
/// # Structure
///
/// An extended private key contains:
/// - **Private Key**: The actual 32-byte secp256k1 private key for signing
/// - **Chain Code**: 32 bytes of entropy used in child key derivation
/// - **Depth**: The depth in the derivation tree (0 for master, 1 for level-1, etc.)
/// - **Parent Fingerprint**: First 4 bytes of parent public key hash (for identification)
/// - **Child Number**: The index of this key in its parent's children
/// - **Network**: The network this key is for (mainnet, testnet, etc.)
///
/// # Serialization Format
///
/// Extended private keys serialize to 78 bytes before Base58Check encoding:
/// ```text
/// [4 bytes]  version        (network-dependent, e.g., 0x0488ADE4 for mainnet)
/// [1 byte]   depth          (0x00 for master)
/// [4 bytes]  fingerprint    (0x00000000 for master)
/// [4 bytes]  child_number   (0x00000000 for master)
/// [32 bytes] chain_code     (entropy for derivation)
/// [33 bytes] key_data       (0x00 + 32-byte private key)
/// ```
///
/// After Base58Check encoding, this becomes the familiar `xprv...` or `tprv...` string.
///
/// # Hardened Derivation
///
/// Child numbers >= 2^31 (0x80000000) represent hardened derivation.
/// Hardened keys cannot be derived from the parent's public key, providing
/// additional security for certain use cases.
///
/// # Examples
///
/// ```rust,ignore
/// use bip32::{ExtendedPrivateKey, Network};
///
/// // Generate master key from seed
/// let seed = [0u8; 64]; // In practice, use BIP-39 mnemonic
/// let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
///
/// // Master key properties
/// assert_eq!(master.depth(), 0);
/// assert_eq!(master.child_number(), 0);
///
/// // Derive a child key
/// let child = master.derive_child(0)?;
/// assert_eq!(child.depth(), 1);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct ExtendedPrivateKey {
    /// The network this key belongs to (Bitcoin mainnet, testnet, etc.)
    network: Network,

    /// Depth in the derivation tree.
    /// - 0 = master key
    /// - 1 = first-level child
    /// - 2 = second-level child
    /// - etc.
    ///
    /// Maximum depth is 255 according to BIP-32.
    depth: u8,

    /// The first 4 bytes of the parent key's public key hash (HASH160).
    /// Used to quickly identify the parent key.
    /// Set to [0, 0, 0, 0] for the master key.
    parent_fingerprint: [u8; 4],

    /// The child index used to derive this key from its parent.
    /// - Values 0 to 2^31-1 (0x7FFFFFFF): normal derivation
    /// - Values 2^31 to 2^32-1 (0x80000000+): hardened derivation
    ///
    /// Set to 0 for the master key.
    child_number: u32,

    /// The chain code used for deriving child keys.
    /// This provides additional entropy beyond the private key itself,
    /// enabling secure hierarchical key derivation.
    chain_code: ChainCode,

    /// The actual secp256k1 private key used for signing transactions
    /// and deriving the corresponding public key.
    private_key: PrivateKey,
}

impl ExtendedPrivateKey {
    /// The maximum allowed depth in the derivation tree.
    /// This is a BIP-32 specification limit.
    pub const MAX_DEPTH: u8 = 255;

    /// The threshold for hardened derivation.
    /// Child numbers >= this value are considered hardened.
    pub const HARDENED_BIT: u32 = 0x80000000; // 2^31
}
