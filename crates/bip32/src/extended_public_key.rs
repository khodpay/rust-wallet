//! Extended public key implementation for BIP32 hierarchical deterministic wallets.
//!
//! This module provides the ExtendedPublicKey type which combines a public key
//! with metadata necessary for hierarchical key derivation according to BIP-32.

use crate::{ChainCode, ChildNumber, Error, Network, PublicKey, Result};
use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

/// An extended public key for BIP32 hierarchical deterministic wallets.
///
/// Extended public keys combine a public key with additional metadata required for
/// hierarchical key derivation. Unlike extended private keys, extended public keys
/// can only derive non-hardened (normal) child keys.
///
/// # Structure
///
/// An extended public key contains:
/// - **Public Key**: The 33-byte compressed secp256k1 public key
/// - **Chain Code**: 32 bytes of entropy used in child key derivation
/// - **Depth**: The depth in the derivation tree (0 for master, 1 for level-1, etc.)
/// - **Parent Fingerprint**: First 4 bytes of parent public key hash (for identification)
/// - **Child Number**: The index of this key in its parent's children
/// - **Network**: The network this key is for (mainnet, testnet, etc.)
///
/// # Serialization Format
///
/// Extended public keys serialize to 78 bytes before Base58Check encoding:
/// ```text
/// [4 bytes]  version        (network-dependent, e.g., 0x0488B21E for mainnet)
/// [1 byte]   depth          (0x00 for master)
/// [4 bytes]  fingerprint    (0x00000000 for master)
/// [4 bytes]  child_number   (0x00000000 for master)
/// [32 bytes] chain_code     (entropy for derivation)
/// [33 bytes] key_data       (33-byte compressed public key)
/// ```
///
/// After Base58Check encoding, this becomes the familiar `xpub...` or `tpub...` string.
///
/// # Limitations
///
/// Extended public keys can only derive **normal (non-hardened)** child keys.
/// Hardened derivation requires the private key and cannot be performed with
/// only the public key. This is a security feature of BIP-32.
///
/// # Use Cases
///
/// Extended public keys are useful for:
/// - **Watch-only wallets**: Monitor balances without signing capability
/// - **Receiving addresses**: Generate new addresses without exposing private keys
/// - **Audit purposes**: Allow third parties to view transaction history
/// - **Point-of-sale systems**: Generate payment addresses without security risk
///
/// # Examples
///
/// ```rust
/// use bip32::{ExtendedPrivateKey, ExtendedPublicKey, Network, ChildNumber};
///
/// // Generate master private key from seed
/// let seed = [0u8; 64];
/// let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
///
/// // Derive extended public key
/// let master_pub = master_priv.to_extended_public_key();
///
/// // Extended public key can derive normal children
/// let child_pub = master_pub.derive_child(ChildNumber::Normal(0))?;  // OK
/// assert_eq!(child_pub.depth(), 1);
///
/// // Hardened derivation from public key will fail
/// // let hardened = master_pub.derive_child(ChildNumber::Hardened(0))?;  // ERROR
/// # Ok::<(), bip32::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct ExtendedPublicKey {
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
    /// - `ChildNumber::Normal(n)`: normal derivation (allowed)
    /// - `ChildNumber::Hardened(n)`: hardened derivation (NOT allowed)
    ///
    /// Set to `ChildNumber::Normal(0)` for the master key.
    ///
    /// **Important**: Extended public keys cannot derive hardened children.
    /// Attempting to derive a hardened child will result in an error.
    child_number: ChildNumber,

    /// The chain code used for deriving child keys.
    /// This provides additional entropy beyond the public key itself,
    /// enabling secure hierarchical key derivation.
    ///
    /// The chain code is the same for corresponding extended private and
    /// public key pairs.
    chain_code: ChainCode,

    /// The compressed secp256k1 public key (33 bytes).
    /// This is used for verification and deriving child public keys.
    public_key: PublicKey,
}

impl ExtendedPublicKey {
    /// The maximum allowed depth in the derivation tree.
    /// This is a BIP-32 specification limit.
    pub const MAX_DEPTH: u8 = 255;

    /// The threshold for hardened derivation.
    /// Child numbers >= this value are considered hardened.
    ///
    /// **Note**: Extended public keys cannot derive hardened children.
    pub const HARDENED_BIT: u32 = 0x80000000; // 2^31

    /// Creates a new `ExtendedPublicKey`.
    ///
    /// # Arguments
    ///
    /// * `network` - The network this key belongs to
    /// * `depth` - Depth in the derivation tree (0 for master)
    /// * `parent_fingerprint` - First 4 bytes of parent public key hash
    /// * `child_number` - Index of this child
    /// * `chain_code` - Chain code for derivation
    /// * `public_key` - The public key
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// // Typically you'd use to_extended_public_key() instead of new()
    /// let seed = [0u8; 64];
    /// let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    /// let master_pub = master_priv.to_extended_public_key();
    ///
    /// assert_eq!(master_pub.depth(), 0);
    /// assert_eq!(master_pub.network(), Network::BitcoinMainnet);
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn new(
        network: Network,
        depth: u8,
        parent_fingerprint: [u8; 4],
        child_number: ChildNumber,
        chain_code: ChainCode,
        public_key: PublicKey,
    ) -> Self {
        ExtendedPublicKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            public_key,
        }
    }

    /// Returns the network this key belongs to.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns the depth of this key in the derivation tree.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Returns the parent fingerprint.
    pub fn parent_fingerprint(&self) -> &[u8; 4] {
        &self.parent_fingerprint
    }

    /// Returns the child number.
    pub fn child_number(&self) -> ChildNumber {
        self.child_number
    }

    /// Returns a reference to the chain code.
    pub fn chain_code(&self) -> &ChainCode {
        &self.chain_code
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Calculates the fingerprint of this extended key.
    ///
    /// The fingerprint is the first 4 bytes of the HASH160 (RIPEMD160(SHA256(public_key)))
    /// of the public key. This is used to identify parent keys in BIP-32 derivation.
    ///
    /// # Important
    ///
    /// - The fingerprint is calculated from the **public key**
    /// - An ExtendedPrivateKey and its corresponding ExtendedPublicKey have
    ///   the **same fingerprint**
    /// - The master key's `parent_fingerprint` is `[0, 0, 0, 0]`, but its own
    ///   `fingerprint()` is derived from its public key (not zero)
    ///
    /// # Algorithm
    ///
    /// ```text
    /// fingerprint = HASH160(public_key)[0..4]
    /// where HASH160(x) = RIPEMD160(SHA256(x))
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::{ExtendedPrivateKey, Network};
    ///
    /// let seed = [0x01; 32];
    /// let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    /// let master_pub = master_priv.to_extended_public_key();
    ///
    /// // Private and public extended keys have the same fingerprint
    /// assert_eq!(master_priv.fingerprint(), master_pub.fingerprint());
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn fingerprint(&self) -> [u8; 4] {
        // Calculate HASH160: RIPEMD160(SHA256(public_key))
        let public_key_bytes = self.public_key.to_bytes();
        
        // Step 1: SHA256
        let sha256_hash = Sha256::digest(&public_key_bytes);
        
        // Step 2: RIPEMD160
        let ripemd160_hash = Ripemd160::digest(&sha256_hash);
        
        // Step 3: Take first 4 bytes
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&ripemd160_hash[0..4]);
        
        fingerprint
    }

    /// Derives a child extended public key from this extended public key.
    ///
    /// This implements the BIP-32 child key derivation (CKD) function for public keys.
    /// **Important**: Only normal (non-hardened) derivation is supported. Hardened derivation
    /// requires the private key and will return an error.
    ///
    /// # Algorithm
    ///
    /// For **normal derivation only** (`ChildNumber::Normal(n)`):
    /// 1. Data = serP(parent_public_key) || ser32(child_number)
    /// 2. I = HMAC-SHA512(Key = parent_chain_code, Data = Data)
    /// 3. Split I into IL (first 32 bytes) and IR (last 32 bytes)
    /// 4. child_public_key = parent_public_key + IL*G (point addition)
    /// 5. child_chain_code = IR
    ///
    /// # Arguments
    ///
    /// * `child_number` - The child number (**must be normal**, hardened will error)
    ///
    /// # Returns
    ///
    /// Returns a new `ExtendedPublicKey` with:
    /// - Incremented depth
    /// - Parent fingerprint set to this key's fingerprint
    /// - Child number set to the provided value
    /// - Derived public key and chain code
    ///
    /// # Errors
    ///
    /// Returns [`Error::HardenedDerivationFromPublicKey`] if trying to derive a hardened child.
    /// Returns [`Error::MaxDepthExceeded`] if this key is already at maximum depth (255).
    /// Returns [`Error::InvalidPublicKey`] if derivation produces an invalid key (extremely rare).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::{ExtendedPrivateKey, ChildNumber, Network};
    ///
    /// let seed = [0u8; 64];
    /// let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    /// let master_pub = master_priv.to_extended_public_key();
    ///
    /// // Normal derivation works
    /// let child = master_pub.derive_child(ChildNumber::Normal(0))?;
    /// assert_eq!(child.depth(), 1);
    ///
    /// // Hardened derivation fails
    /// let result = master_pub.derive_child(ChildNumber::Hardened(0));
    /// assert!(result.is_err());
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn derive_child(&self, child_number: ChildNumber) -> Result<Self> {
        // Check if trying to derive hardened child
        if child_number.is_hardened() {
            return Err(Error::HardenedDerivationFromPublicKey {
                index: child_number.to_index(),
            });
        }

        // Check if we can derive a child (depth limit)
        if self.depth == Self::MAX_DEPTH {
            return Err(Error::MaxDepthExceeded {
                depth: Self::MAX_DEPTH,
            });
        }

        // Prepare HMAC-SHA512
        type HmacSha512 = Hmac<Sha512>;
        let mut hmac = HmacSha512::new_from_slice(self.chain_code.as_bytes())
            .expect("HMAC can take key of any size");

        // For normal derivation: use public key
        // Data = public_key (33 bytes compressed) || child_number (4 bytes)
        hmac.update(&self.public_key.to_bytes());
        hmac.update(&child_number.to_index().to_be_bytes());

        // Compute HMAC-SHA512
        let result = hmac.finalize().into_bytes();

        // Split into IL (first 32 bytes) and IR (last 32 bytes)
        let (il, ir) = result.split_at(32);

        // IL becomes the tweak to add to parent public key
        // child_public_key = parent_public_key + IL*G
        let child_public_key = self.public_key.tweak_add(il)?;

        // IR becomes the child chain code
        let child_chain_code = ChainCode::from_bytes(ir)?;

        // Calculate parent fingerprint (first 4 bytes of HASH160 of parent public key)
        let parent_fingerprint = self.fingerprint();

        Ok(ExtendedPublicKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number,
            chain_code: child_chain_code,
            public_key: child_public_key,
        })
    }

    /// Derives an extended public key from a derivation path.
    ///
    /// This is a convenience method that iteratively calls `derive_child()` for each
    /// component in the path. **Important**: Only normal (non-hardened) derivation is
    /// supported. Any hardened child number in the path will return an error.
    ///
    /// # Arguments
    ///
    /// * `path` - A `DerivationPath` specifying the full derivation
    ///
    /// # Returns
    ///
    /// Returns the extended public key at the end of the derivation path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HardenedDerivationFromPublicKey`] if any step in the path is hardened.
    /// Returns an error if any step of the derivation fails (e.g., max depth exceeded).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::{ExtendedPrivateKey, DerivationPath, Network};
    /// use std::str::FromStr;
    ///
    /// let seed = [0u8; 64];
    /// let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    /// let master_pub = master_priv.to_extended_public_key();
    ///
    /// // Normal derivation works
    /// let path = DerivationPath::from_str("m/0/1/2")?;
    /// let child = master_pub.derive_path(&path)?;
    /// assert_eq!(child.depth(), 3);
    ///
    /// // Hardened derivation fails
    /// let hardened_path = DerivationPath::from_str("m/0'/1")?;
    /// assert!(master_pub.derive_path(&hardened_path).is_err());
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn derive_path(&self, path: &crate::DerivationPath) -> Result<Self> {
        // Start with current key
        let mut current = self.clone();
        
        // Derive each child in the path
        // Will fail if any child number is hardened
        for child_number in path.iter() {
            current = current.derive_child(*child_number)?;
        }
        
        Ok(current)
    }
}

impl std::fmt::Debug for ExtendedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedPublicKey")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &hex::encode(self.chain_code.as_bytes()))
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl std::fmt::Display for ExtendedPublicKey {
    /// Serializes the extended public key to Base58Check encoding (xpub/tpub format).
    ///
    /// Format per BIP-32:
    /// - 4 bytes: version bytes (network-specific)
    /// - 1 byte: depth
    /// - 4 bytes: parent fingerprint
    /// - 4 bytes: child number (big-endian)
    /// - 32 bytes: chain code
    /// - 33 bytes: compressed public key
    /// - 4 bytes: checksum (first 4 bytes of double SHA256)
    ///
    /// Total: 82 bytes, then Base58 encoded
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use sha2::{Digest, Sha256};
        
        // Build the 78-byte payload
        let mut data = Vec::with_capacity(78);
        
        // 1. Version bytes (4 bytes) - network specific
        data.extend_from_slice(&self.network.xpub_version().to_be_bytes());
        
        // 2. Depth (1 byte)
        data.push(self.depth);
        
        // 3. Parent fingerprint (4 bytes)
        data.extend_from_slice(&self.parent_fingerprint);
        
        // 4. Child number (4 bytes, big-endian)
        data.extend_from_slice(&self.child_number.to_index().to_be_bytes());
        
        // 5. Chain code (32 bytes)
        data.extend_from_slice(self.chain_code.as_bytes());
        
        // 6. Public key data (33 bytes) - compressed public key
        data.extend_from_slice(&self.public_key.to_bytes());
        
        debug_assert_eq!(data.len(), 78, "Serialized data must be exactly 78 bytes");
        
        // 7. Compute checksum: first 4 bytes of SHA256(SHA256(data))
        let hash1 = Sha256::digest(&data);
        let hash2 = Sha256::digest(&hash1);
        let checksum = &hash2[0..4];
        
        // 8. Append checksum to get 82 bytes total
        data.extend_from_slice(checksum);
        
        debug_assert_eq!(data.len(), 82, "Final data must be exactly 82 bytes");
        
        // 9. Base58 encode
        let encoded = bs58::encode(&data).into_string();
        
        write!(f, "{}", encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DerivationPath, ExtendedPrivateKey};
    use std::str::FromStr;

    // Helper to create an ExtendedPublicKey for testing
    fn create_test_extended_public_key() -> ExtendedPublicKey {
        let seed = [0x01; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        ext_priv.to_extended_public_key()
    }

    #[test]
    fn test_extended_public_key_new() {
        let seed = [0xAA; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let public_key = PublicKey::from_private_key(ext_priv.private_key());
        let chain_code = ChainCode::new([0x42; 32]);

        let ext_pub = ExtendedPublicKey::new(
            Network::BitcoinMainnet,
            2,
            [0x3A, 0x4F, 0x8B, 0xC2],
            ChildNumber::Normal(5),
            chain_code.clone(),
            public_key.clone(),
        );

        assert_eq!(ext_pub.network(), Network::BitcoinMainnet);
        assert_eq!(ext_pub.depth(), 2);
        assert_eq!(ext_pub.parent_fingerprint(), &[0x3A, 0x4F, 0x8B, 0xC2]);
        assert_eq!(ext_pub.child_number(), ChildNumber::Normal(5));
        assert_eq!(ext_pub.chain_code(), &chain_code);
        assert_eq!(ext_pub.public_key(), &public_key);
    }

    #[test]
    fn test_extended_public_key_getters() {
        let ext_pub = create_test_extended_public_key();

        // Test all getters
        assert_eq!(ext_pub.network(), Network::BitcoinMainnet);
        assert_eq!(ext_pub.depth(), 0); // Master key
        assert_eq!(ext_pub.parent_fingerprint(), &[0, 0, 0, 0]); // Master key
        assert_eq!(ext_pub.child_number(), ChildNumber::Normal(0)); // Master key
        assert_eq!(ext_pub.chain_code().as_bytes().len(), 32);
        assert_eq!(ext_pub.public_key().to_bytes().len(), 33); // Compressed
    }

    #[test]
    fn test_extended_public_key_clone() {
        let ext_pub1 = create_test_extended_public_key();
        let ext_pub2 = ext_pub1.clone();

        assert_eq!(ext_pub1, ext_pub2);
        assert_eq!(ext_pub1.network(), ext_pub2.network());
        assert_eq!(ext_pub1.depth(), ext_pub2.depth());
        assert_eq!(ext_pub1.public_key().to_bytes(), ext_pub2.public_key().to_bytes());
    }

    #[test]
    fn test_extended_public_key_equality() {
        let ext_pub1 = create_test_extended_public_key();
        let ext_pub2 = create_test_extended_public_key();

        // Same seed should produce same key
        assert_eq!(ext_pub1, ext_pub2);
    }

    #[test]
    fn test_extended_public_key_inequality() {
        let seed1 = [0x01; 32];
        let seed2 = [0x02; 32];
        
        let ext_priv1 = ExtendedPrivateKey::from_seed(&seed1, Network::BitcoinMainnet).unwrap();
        let ext_priv2 = ExtendedPrivateKey::from_seed(&seed2, Network::BitcoinMainnet).unwrap();
        
        let ext_pub1 = ext_priv1.to_extended_public_key();
        let ext_pub2 = ext_priv2.to_extended_public_key();

        // Different seeds should produce different keys
        assert_ne!(ext_pub1, ext_pub2);
    }

    #[test]
    fn test_extended_public_key_fingerprint() {
        let ext_pub = create_test_extended_public_key();
        let fingerprint = ext_pub.fingerprint();

        // Fingerprint should be 4 bytes
        assert_eq!(fingerprint.len(), 4);
    }

    #[test]
    fn test_extended_public_key_fingerprint_deterministic() {
        let ext_pub = create_test_extended_public_key();
        
        let fingerprint1 = ext_pub.fingerprint();
        let fingerprint2 = ext_pub.fingerprint();

        assert_eq!(fingerprint1, fingerprint2);
    }

    #[test]
    fn test_extended_public_key_fingerprint_matches_private() {
        let seed = [0x03; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();

        // Private and public extended keys should have the same fingerprint
        assert_eq!(ext_priv.fingerprint(), ext_pub.fingerprint());
    }

    #[test]
    fn test_extended_public_key_debug() {
        let ext_pub = create_test_extended_public_key();
        let debug_output = format!("{:?}", ext_pub);

        // Should contain all public information
        assert!(debug_output.contains("ExtendedPublicKey"));
        assert!(debug_output.contains("network"));
        assert!(debug_output.contains("depth"));
        assert!(debug_output.contains("parent_fingerprint"));
        assert!(debug_output.contains("child_number"));
        assert!(debug_output.contains("chain_code"));
        assert!(debug_output.contains("public_key"));

        // Unlike ExtendedPrivateKey, this should show actual data (not redacted)
        assert!(!debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_extended_public_key_different_networks() {
        let seed = [0x04; 32];
        
        let mainnet_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let testnet_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        
        let mainnet_pub = mainnet_priv.to_extended_public_key();
        let testnet_pub = testnet_priv.to_extended_public_key();

        assert_eq!(mainnet_pub.network(), Network::BitcoinMainnet);
        assert_eq!(testnet_pub.network(), Network::BitcoinTestnet);
        
        // Same seed but different networks
        assert_ne!(mainnet_pub.network(), testnet_pub.network());
        
        // Keys and chain codes should be the same (only network differs)
        assert_eq!(mainnet_pub.public_key().to_bytes(), testnet_pub.public_key().to_bytes());
        assert_eq!(mainnet_pub.chain_code().as_bytes(), testnet_pub.chain_code().as_bytes());
    }

    #[test]
    fn test_extended_public_key_master_properties() {
        let ext_pub = create_test_extended_public_key();

        // Master key properties
        assert_eq!(ext_pub.depth(), 0);
        assert_eq!(ext_pub.child_number(), ChildNumber::Normal(0));
        assert_eq!(ext_pub.parent_fingerprint(), &[0, 0, 0, 0]);
        
        // But fingerprint should not be zero
        assert_ne!(ext_pub.fingerprint(), [0, 0, 0, 0]);
    }

    #[test]
    fn test_extended_public_key_constants() {
        // Verify the constants are defined correctly
        assert_eq!(ExtendedPublicKey::MAX_DEPTH, 255);
        assert_eq!(ExtendedPublicKey::HARDENED_BIT, 0x80000000);
    }

    #[test]
    fn test_extended_public_key_new_with_max_depth() {
        let seed = [0xBB; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let public_key = PublicKey::from_private_key(ext_priv.private_key());
        let chain_code = ChainCode::new([0x42; 32]);

        let ext_pub = ExtendedPublicKey::new(
            Network::BitcoinMainnet,
            ExtendedPublicKey::MAX_DEPTH,
            [0xFF, 0xFF, 0xFF, 0xFF],
            ChildNumber::Hardened(0x7FFFFFFF),
            chain_code,
            public_key,
        );

        assert_eq!(ext_pub.depth(), 255);
        assert_eq!(ext_pub.child_number(), ChildNumber::Hardened(0x7FFFFFFF));
    }

    #[test]
    fn test_extended_public_key_chain_code_independence() {
        // Test that different chain codes create different extended keys
        let seed = [0xCC; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let public_key = PublicKey::from_private_key(ext_priv.private_key());
        let chain_code1 = ChainCode::new([0x01; 32]);
        let chain_code2 = ChainCode::new([0x02; 32]);

        let ext_pub1 = ExtendedPublicKey::new(
            Network::BitcoinMainnet,
            0,
            [0, 0, 0, 0],
            ChildNumber::Normal(0),
            chain_code1,
            public_key.clone(),
        );

        let ext_pub2 = ExtendedPublicKey::new(
            Network::BitcoinMainnet,
            0,
            [0, 0, 0, 0],
            ChildNumber::Normal(0),
            chain_code2,
            public_key,
        );

        // Same public key but different chain codes
        assert_ne!(ext_pub1, ext_pub2);
        assert_ne!(ext_pub1.chain_code(), ext_pub2.chain_code());
    }

    #[test]
    fn test_derive_child_normal_basic() {
        let seed = [0x01; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Derive first normal child (index 0)
        let child = ext_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        
        // Child should have incremented depth
        assert_eq!(child.depth(), 1);
        assert_eq!(child.child_number(), ChildNumber::Normal(0));
        
        // Parent fingerprint should be master's fingerprint
        assert_eq!(child.parent_fingerprint(), &ext_pub.fingerprint());
        
        // Network should be preserved
        assert_eq!(child.network(), ext_pub.network());
        
        // Key and chain code should be different from parent
        assert_ne!(child.public_key().to_bytes(), ext_pub.public_key().to_bytes());
        assert_ne!(child.chain_code().as_bytes(), ext_pub.chain_code().as_bytes());
    }

    #[test]
    fn test_derive_child_normal_multiple_indices() {
        let seed = [0x02; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Derive different normal children
        let child0 = ext_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        let child1 = ext_pub.derive_child(ChildNumber::Normal(1)).unwrap();
        let child100 = ext_pub.derive_child(ChildNumber::Normal(100)).unwrap();
        
        // All should have depth 1
        assert_eq!(child0.depth(), 1);
        assert_eq!(child1.depth(), 1);
        assert_eq!(child100.depth(), 1);
        
        // Child numbers should match indices
        assert_eq!(child0.child_number(), ChildNumber::Normal(0));
        assert_eq!(child1.child_number(), ChildNumber::Normal(1));
        assert_eq!(child100.child_number(), ChildNumber::Normal(100));
        
        // All should have same parent fingerprint
        let parent_fp = ext_pub.fingerprint();
        assert_eq!(child0.parent_fingerprint(), &parent_fp);
        assert_eq!(child1.parent_fingerprint(), &parent_fp);
        assert_eq!(child100.parent_fingerprint(), &parent_fp);
        
        // Keys should all be different
        assert_ne!(child0.public_key().to_bytes(), child1.public_key().to_bytes());
        assert_ne!(child0.public_key().to_bytes(), child100.public_key().to_bytes());
        assert_ne!(child1.public_key().to_bytes(), child100.public_key().to_bytes());
    }

    #[test]
    fn test_derive_child_hardened_rejected() {
        let seed = [0x03; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Attempting hardened derivation should fail
        let result = ext_pub.derive_child(ChildNumber::Hardened(0));
        assert!(result.is_err());
        
        match result {
            Err(Error::HardenedDerivationFromPublicKey { index }) => {
                assert_eq!(index, 0x80000000); // 2^31 + 0
            }
            _ => panic!("Expected HardenedDerivationFromPublicKey error"),
        }
    }

    #[test]
    fn test_derive_child_hardened_rejected_multiple() {
        let seed = [0x04; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // All hardened derivations should fail
        assert!(ext_pub.derive_child(ChildNumber::Hardened(0)).is_err());
        assert!(ext_pub.derive_child(ChildNumber::Hardened(1)).is_err());
        assert!(ext_pub.derive_child(ChildNumber::Hardened(44)).is_err());
    }

    #[test]
    fn test_derive_child_matches_private_derivation() {
        // Critical: public key derivation should match private key derivation for normal children
        let seed = [0x05; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Derive child from private key
        let priv_child = ext_priv.derive_child(ChildNumber::Normal(0)).unwrap();
        let pub_from_priv = priv_child.to_extended_public_key();
        
        // Derive child from public key
        let pub_child = ext_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        
        // Should produce identical public keys
        assert_eq!(pub_from_priv, pub_child);
        assert_eq!(pub_from_priv.public_key().to_bytes(), pub_child.public_key().to_bytes());
        assert_eq!(pub_from_priv.chain_code().as_bytes(), pub_child.chain_code().as_bytes());
    }

    #[test]
    fn test_derive_child_deterministic() {
        let seed = [0x06; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Derive same child twice
        let child1 = ext_pub.derive_child(ChildNumber::Normal(5)).unwrap();
        let child2 = ext_pub.derive_child(ChildNumber::Normal(5)).unwrap();
        
        // Should be identical
        assert_eq!(child1, child2);
        assert_eq!(child1.public_key().to_bytes(), child2.public_key().to_bytes());
        assert_eq!(child1.chain_code().as_bytes(), child2.chain_code().as_bytes());
    }

    #[test]
    fn test_derive_child_multi_level() {
        let seed = [0x07; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Derive child, then grandchild
        let child = ext_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        let grandchild = child.derive_child(ChildNumber::Normal(0)).unwrap();
        
        // Depths should increase
        assert_eq!(ext_pub.depth(), 0);
        assert_eq!(child.depth(), 1);
        assert_eq!(grandchild.depth(), 2);
        
        // Grandchild's parent fingerprint should be child's fingerprint
        assert_eq!(grandchild.parent_fingerprint(), &child.fingerprint());
        assert_ne!(grandchild.parent_fingerprint(), &ext_pub.fingerprint());
    }

    #[test]
    fn test_derive_child_preserves_network() {
        let seed = [0x08; 32];
        
        let mainnet_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let mainnet_pub = mainnet_priv.to_extended_public_key();
        let mainnet_child = mainnet_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        
        let testnet_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        let testnet_pub = testnet_priv.to_extended_public_key();
        let testnet_child = testnet_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        
        assert_eq!(mainnet_child.network(), Network::BitcoinMainnet);
        assert_eq!(testnet_child.network(), Network::BitcoinTestnet);
        
        // Keys should be same (network doesn't affect derivation)
        assert_eq!(mainnet_child.public_key().to_bytes(), testnet_child.public_key().to_bytes());
    }

    #[test]
    fn test_derive_child_max_normal_index() {
        let seed = [0x09; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Maximum normal child index is 2^31 - 1
        let max_normal_index = ChildNumber::MAX_NORMAL_INDEX;
        let child = ext_pub.derive_child(ChildNumber::Normal(max_normal_index)).unwrap();
        
        assert_eq!(child.child_number(), ChildNumber::Normal(max_normal_index));
        assert_eq!(child.depth(), 1);
    }

    #[test]
    fn test_derive_child_depth_overflow() {
        let seed = [0x0A; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Manually create a public key at max depth
        let max_depth_key = ExtendedPublicKey {
            network: ext_pub.network(),
            depth: ExtendedPublicKey::MAX_DEPTH,
            parent_fingerprint: [0; 4],
            child_number: ChildNumber::Normal(0),
            chain_code: ext_pub.chain_code().clone(),
            public_key: ext_pub.public_key().clone(),
        };
        
        // Trying to derive a child should fail
        let result = max_depth_key.derive_child(ChildNumber::Normal(0));
        assert!(result.is_err());
        
        match result {
            Err(Error::MaxDepthExceeded { depth }) => {
                assert_eq!(depth, ExtendedPublicKey::MAX_DEPTH);
            }
            _ => panic!("Expected MaxDepthExceeded error"),
        }
    }

    #[test]
    fn test_derive_child_bip32_test_vector() {
        // BIP-32 Test Vector 1: Derive m/0 from public key
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let master_pub = master_priv.to_extended_public_key();
        
        // Derive m/0 from public key (normal derivation)
        let child_pub = master_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        
        // Derive m/0 from private key and convert to public
        let child_priv = master_priv.derive_child(ChildNumber::Normal(0)).unwrap();
        let expected_pub = child_priv.to_extended_public_key();
        
        // They should match
        assert_eq!(child_pub.public_key().to_bytes(), expected_pub.public_key().to_bytes());
        assert_eq!(child_pub.chain_code().as_bytes(), expected_pub.chain_code().as_bytes());
    }

    #[test]
    fn test_derive_child_deep_path() {
        let seed = [0x0B; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let mut ext_pub = ext_priv.to_extended_public_key();
        
        // Derive a deep path (all normal, no hardened)
        for i in 0..10 {
            ext_pub = ext_pub.derive_child(ChildNumber::Normal(i)).unwrap();
            assert_eq!(ext_pub.depth(), (i + 1) as u8);
            assert_eq!(ext_pub.child_number(), ChildNumber::Normal(i));
        }
        
        assert_eq!(ext_pub.depth(), 10);
    }

    #[test]
    fn test_derive_path_master_key() {
        let seed = [0x01; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Master path "m" should return same key
        let path = DerivationPath::from_str("m").unwrap();
        let result = ext_pub.derive_path(&path).unwrap();
        
        assert_eq!(result, ext_pub);
    }

    #[test]
    fn test_derive_path_single_level() {
        let seed = [0x02; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Single level path "m/0"
        let path = DerivationPath::from_str("m/0").unwrap();
        let derived = ext_pub.derive_path(&path).unwrap();
        
        // Should be same as derive_child
        let expected = ext_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_derive_path_multi_level() {
        let seed = [0x03; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Multi-level path "m/0/1/2" (all normal)
        let path = DerivationPath::from_str("m/0/1/2").unwrap();
        let derived = ext_pub.derive_path(&path).unwrap();
        
        // Manual derivation
        let child_0 = ext_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        let child_0_1 = child_0.derive_child(ChildNumber::Normal(1)).unwrap();
        let child_0_1_2 = child_0_1.derive_child(ChildNumber::Normal(2)).unwrap();
        
        assert_eq!(derived, child_0_1_2);
        assert_eq!(derived.depth(), 3);
    }

    #[test]
    fn test_derive_path_hardened_rejected() {
        let seed = [0x04; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Hardened path should fail
        let path = DerivationPath::from_str("m/0'").unwrap();
        let result = ext_pub.derive_path(&path);
        
        assert!(result.is_err());
        match result {
            Err(Error::HardenedDerivationFromPublicKey { .. }) => {
                // Expected
            }
            _ => panic!("Expected HardenedDerivationFromPublicKey error"),
        }
    }

    #[test]
    fn test_derive_path_mixed_hardened_rejected() {
        let seed = [0x05; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Mixed path with hardened should fail at first hardened step
        let path = DerivationPath::from_str("m/0/1'/2").unwrap();
        let result = ext_pub.derive_path(&path);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_path_matches_private_derivation() {
        // Critical: public path derivation should match private path derivation for normal paths
        let seed = [0x06; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        let path = DerivationPath::from_str("m/0/1/2").unwrap();
        
        // Derive from private key and convert to public
        let priv_derived = ext_priv.derive_path(&path).unwrap();
        let pub_from_priv = priv_derived.to_extended_public_key();
        
        // Derive from public key
        let pub_derived = ext_pub.derive_path(&path).unwrap();
        
        // Should produce identical public keys
        assert_eq!(pub_from_priv, pub_derived);
        assert_eq!(pub_from_priv.public_key().to_bytes(), pub_derived.public_key().to_bytes());
        assert_eq!(pub_from_priv.chain_code().as_bytes(), pub_derived.chain_code().as_bytes());
    }

    #[test]
    fn test_derive_path_deterministic() {
        let seed = [0x07; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        let path = DerivationPath::from_str("m/0/1/2").unwrap();
        
        // Derive same path twice
        let derived1 = ext_pub.derive_path(&path).unwrap();
        let derived2 = ext_pub.derive_path(&path).unwrap();
        
        assert_eq!(derived1, derived2);
    }

    #[test]
    fn test_derive_path_preserves_network() {
        let seed = [0x08; 32];
        
        let mainnet_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let mainnet_pub = mainnet_priv.to_extended_public_key();
        
        let testnet_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        let testnet_pub = testnet_priv.to_extended_public_key();
        
        let path = DerivationPath::from_str("m/0/1").unwrap();
        
        let mainnet_derived = mainnet_pub.derive_path(&path).unwrap();
        let testnet_derived = testnet_pub.derive_path(&path).unwrap();
        
        assert_eq!(mainnet_derived.network(), Network::BitcoinMainnet);
        assert_eq!(testnet_derived.network(), Network::BitcoinTestnet);
    }

    #[test]
    fn test_derive_path_deep() {
        let seed = [0x09; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();
        
        // Create a deep path (10 levels, all normal)
        let path = DerivationPath::from_str("m/0/1/2/3/4/5/6/7/8/9").unwrap();
        let derived = ext_pub.derive_path(&path).unwrap();
        
        assert_eq!(derived.depth(), 10);
        assert_eq!(derived.child_number(), ChildNumber::Normal(9));
    }

    #[test]
    fn test_derive_path_bip32_test_vector() {
        // BIP-32 Test Vector 1: m/0/1 from public key (all normal)
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // First derive m/0' with private key (hardened)
        let child_0h_priv = master_priv.derive_child(ChildNumber::Hardened(0)).unwrap();
        let child_0h_pub = child_0h_priv.to_extended_public_key();
        
        // Now derive m/0'/1 from public key (normal from hardened parent)
        let path = DerivationPath::from_str("m/1").unwrap();
        let derived_pub = child_0h_pub.derive_path(&path).unwrap();
        
        // Verify against private derivation
        let expected_priv = child_0h_priv.derive_child(ChildNumber::Normal(1)).unwrap();
        let expected_pub = expected_priv.to_extended_public_key();
        
        assert_eq!(derived_pub.public_key().to_bytes(), expected_pub.public_key().to_bytes());
    }

    #[test]
    fn test_derive_path_watch_only_use_case() {
        // Real-world scenario: Watch-only wallet deriving addresses
        let seed = [0x0A; 32];
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive account level with private key (m/44'/0'/0')
        let account_priv = master_priv.derive_path(&DerivationPath::from_str("m/44'/0'/0'").unwrap()).unwrap();
        
        // Get account xpub (share this for watch-only)
        let account_pub = account_priv.to_extended_public_key();
        
        // Watch-only wallet can now derive addresses (m/0/0, m/0/1, etc.)
        for i in 0..5 {
            let addr_path = DerivationPath::from_str(&format!("m/0/{}", i)).unwrap();
            let address_pub = account_pub.derive_path(&addr_path).unwrap();
            
            assert_eq!(address_pub.depth(), account_pub.depth() + 2);
            assert_eq!(address_pub.child_number(), ChildNumber::Normal(i));
        }
    }

    // ========================================================================
    // Task 47: Tests for Base58Check serialization (xpub format)
    // ========================================================================

    #[test]
    fn test_serialize_master_public_key_mainnet() {
        // BIP-32 Test Vector 1: Master key -> public key
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let master_pub = master_priv.to_extended_public_key();
        
        let serialized = master_pub.to_string();
        
        // Expected from BIP-32 test vectors
        let expected = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_master_public_key_testnet() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        let master_pub = master_priv.to_extended_public_key();
        
        let serialized = master_pub.to_string();
        
        // Should start with "tpub" for testnet
        assert!(serialized.starts_with("tpub"));
        
        // Should be valid base58
        assert!(bs58::decode(&serialized).into_vec().is_ok());
    }

    #[test]
    fn test_serialize_derived_public_key_normal() {
        // BIP-32 Test Vector 1: m/0'/1 -> public key
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/0'/1").unwrap();
        let child_priv = master_priv.derive_path(&path).unwrap();
        let child_pub = child_priv.to_extended_public_key();
        
        let serialized = child_pub.to_string();
        
        // Expected from BIP-32 test vectors
        let expected = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_deep_derivation_public() {
        // BIP-32 Test Vector 1: m/0'/1/2'/2 -> public key
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/0'/1/2'/2").unwrap();
        let child_priv = master_priv.derive_path(&path).unwrap();
        let child_pub = child_priv.to_extended_public_key();
        
        let serialized = child_pub.to_string();
        
        // Expected from BIP-32 test vectors
        let expected = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV";
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_public_length() {
        let seed = [0x01; 32];
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let master_pub = master_priv.to_extended_public_key();
        
        let serialized = master_pub.to_string();
        
        // Base58 encoded extended keys should decode to exactly 82 bytes
        // (78 bytes data + 4 bytes checksum)
        let decoded = bs58::decode(&serialized).into_vec().unwrap();
        assert_eq!(decoded.len(), 82);
    }

    #[test]
    fn test_serialize_public_starts_with_xpub_mainnet() {
        let seed = [0x02; 32];
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let master_pub = master_priv.to_extended_public_key();
        
        let serialized = master_pub.to_string();
        
        // Mainnet public keys should start with "xpub"
        assert!(serialized.starts_with("xpub"));
    }

    #[test]
    fn test_serialize_public_starts_with_tpub_testnet() {
        let seed = [0x03; 32];
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        let master_pub = master_priv.to_extended_public_key();
        
        let serialized = master_pub.to_string();
        
        // Testnet public keys should start with "tpub"
        assert!(serialized.starts_with("tpub"));
    }

    #[test]
    fn test_serialize_public_deterministic() {
        let seed = [0x04; 32];
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let master_pub = master_priv.to_extended_public_key();
        
        // Serialize same key twice
        let serialized1 = master_pub.to_string();
        let serialized2 = master_pub.to_string();
        
        // Should produce identical output
        assert_eq!(serialized1, serialized2);
    }

    #[test]
    fn test_serialize_public_different_keys_different_output() {
        let master_priv1 = ExtendedPrivateKey::from_seed(&[0x01; 32], Network::BitcoinMainnet).unwrap();
        let master_priv2 = ExtendedPrivateKey::from_seed(&[0x02; 32], Network::BitcoinMainnet).unwrap();
        
        let master_pub1 = master_priv1.to_extended_public_key();
        let master_pub2 = master_priv2.to_extended_public_key();
        
        let serialized1 = master_pub1.to_string();
        let serialized2 = master_pub2.to_string();
        
        // Different keys should produce different serializations
        assert_ne!(serialized1, serialized2);
    }

    #[test]
    fn test_serialize_public_different_networks_different_output() {
        let seed = [0x05; 32];
        let mainnet_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let testnet_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        
        let mainnet_pub = mainnet_priv.to_extended_public_key();
        let testnet_pub = testnet_priv.to_extended_public_key();
        
        let mainnet_serialized = mainnet_pub.to_string();
        let testnet_serialized = testnet_pub.to_string();
        
        // Same seed but different networks should produce different serializations
        assert_ne!(mainnet_serialized, testnet_serialized);
        assert!(mainnet_serialized.starts_with("xpub"));
        assert!(testnet_serialized.starts_with("tpub"));
    }

    #[test]
    fn test_serialize_public_checksum_validation() {
        let seed = [0x06; 32];
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let master_pub = master_priv.to_extended_public_key();
        
        let serialized = master_pub.to_string();
        
        // Should decode successfully (bs58 library validates structure)
        let result = bs58::decode(&serialized).into_vec();
        assert!(result.is_ok());
    }

    #[test]
    fn test_serialize_public_bip32_test_vector_2_master() {
        // BIP-32 Test Vector 2: Different seed -> public key
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let master_pub = master_priv.to_extended_public_key();
        
        let serialized = master_pub.to_string();
        
        // Expected from BIP-32 test vector 2
        let expected = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_public_bip32_test_vector_2_derived() {
        // BIP-32 Test Vector 2: m/0 -> public key
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let child_priv = master_priv.derive_child(ChildNumber::Normal(0)).unwrap();
        let child_pub = child_priv.to_extended_public_key();
        
        let serialized = child_pub.to_string();
        
        // Expected from BIP-32 test vector 2
        let expected = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_public_preserves_all_fields() {
        let seed = [0x07; 32];
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        let derived_priv = master_priv.derive_path(&path).unwrap();
        let derived_pub = derived_priv.to_extended_public_key();
        
        let serialized = derived_pub.to_string();
        let decoded = bs58::decode(&serialized).into_vec().unwrap();
        
        // Verify structure (without implementing deserialization yet)
        assert_eq!(decoded.len(), 82); // 78 bytes + 4 checksum
        
        // Version bytes (first 4 bytes) should be mainnet xpub
        assert_eq!(&decoded[0..4], &Network::BitcoinMainnet.xpub_version().to_be_bytes());
        
        // Depth should be 3
        assert_eq!(decoded[4], 3);
    }

    #[test]
    fn test_serialize_public_watch_only_use_case() {
        // Real-world scenario: Export xpub for watch-only wallet
        let seed = [0x08; 32];
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive account (m/44'/0'/0')
        let account_priv = master_priv.derive_path(&DerivationPath::from_str("m/44'/0'/0'").unwrap()).unwrap();
        let account_pub = account_priv.to_extended_public_key();
        
        // Serialize for sharing with watch-only wallet
        let xpub = account_pub.to_string();
        
        // Verify it's a valid xpub
        assert!(xpub.starts_with("xpub"));
        assert_eq!(account_pub.depth(), 3);
        
        // The xpub can be shared without exposing private keys
        let decoded = bs58::decode(&xpub).into_vec().unwrap();
        assert_eq!(decoded.len(), 82);
    }
}
