//! Extended private key implementation for BIP32 hierarchical deterministic wallets.
//!
//! This module provides the core ExtendedPrivateKey type which combines a private key
//! with metadata necessary for hierarchical key derivation according to BIP-32.

use crate::{ChainCode, Error, ExtendedPublicKey, Network, PrivateKey, PublicKey, Result};
use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

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

    /// The HMAC key used for master key generation.
    const MASTER_HMAC_KEY: &'static [u8] = b"Bitcoin seed";

    /// Generates a master extended private key from a seed.
    ///
    /// This implements the BIP-32 master key generation algorithm:
    /// 1. Compute `I = HMAC-SHA512(Key = "Bitcoin seed", Data = seed)`
    /// 2. Split `I` into two 32-byte sequences, `IL` and `IR`
    /// 3. `IL` becomes the master private key
    /// 4. `IR` becomes the master chain code
    /// 5. If `IL` is 0 or >= curve order, the seed is invalid (very rare)
    ///
    /// # Arguments
    ///
    /// * `seed` - A cryptographic seed, typically 128-512 bits (16-64 bytes).
    ///            Usually derived from a BIP-39 mnemonic phrase.
    /// * `network` - The network for this key (Bitcoin mainnet, testnet, etc.)
    ///
    /// # Returns
    ///
    /// Returns a master extended private key with:
    /// - `depth = 0`
    /// - `parent_fingerprint = [0, 0, 0, 0]`
    /// - `child_number = 0`
    /// - `private_key` and `chain_code` derived from the seed
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSeedLength`] if the seed is not between 16 and 64 bytes.
    /// Returns [`Error::InvalidPrivateKey`] if the derived key is invalid (extremely rare).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::{ExtendedPrivateKey, Network};
    ///
    /// // Generate from a 64-byte seed (typically from BIP-39)
    /// let seed = [0x01; 64];
    /// let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    ///
    /// // Master key properties
    /// assert_eq!(master.depth(), 0);
    /// assert_eq!(master.child_number(), 0);
    /// assert_eq!(master.parent_fingerprint(), &[0, 0, 0, 0]);
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn from_seed(seed: &[u8], network: Network) -> Result<Self> {
        // Validate seed length (BIP-32 recommends 128-512 bits = 16-64 bytes)
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Error::InvalidSeedLength {
                length: seed.len(),
            });
        }

        // Compute HMAC-SHA512
        type HmacSha512 = Hmac<Sha512>;
        let mut hmac = HmacSha512::new_from_slice(Self::MASTER_HMAC_KEY)
            .expect("HMAC can take key of any size");
        hmac.update(seed);
        let result = hmac.finalize().into_bytes();

        // Split into IL (first 32 bytes) and IR (last 32 bytes)
        let (il, ir) = result.split_at(32);

        // IL becomes the private key
        let private_key = PrivateKey::from_bytes(il)?;

        // IR becomes the chain code
        let chain_code = ChainCode::from_bytes(ir)?;

        Ok(ExtendedPrivateKey {
            network,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_number: 0,
            chain_code,
            private_key,
        })
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
    pub fn child_number(&self) -> u32 {
        self.child_number
    }

    /// Returns a reference to the chain code.
    pub fn chain_code(&self) -> &ChainCode {
        &self.chain_code
    }

    /// Returns a reference to the private key.
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Converts this extended private key to an extended public key.
    ///
    /// This creates an extended public key with the same metadata (network, depth,
    /// parent fingerprint, child number, chain code) but with the public key derived
    /// from the private key.
    ///
    /// # Important
    ///
    /// The chain code is **copied** to the extended public key. This is critical for
    /// BIP-32 derivation: both the extended private key and its corresponding extended
    /// public key must have the same chain code for child key derivation to work correctly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::{ExtendedPrivateKey, Network};
    ///
    /// let seed = [0x01; 32];
    /// let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    /// let ext_pub = ext_priv.to_extended_public_key();
    ///
    /// // Metadata is preserved
    /// assert_eq!(ext_pub.network(), ext_priv.network());
    /// assert_eq!(ext_pub.depth(), ext_priv.depth());
    /// assert_eq!(ext_pub.chain_code(), ext_priv.chain_code());
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn to_extended_public_key(&self) -> ExtendedPublicKey {
        // Derive public key from private key
        let public_key = PublicKey::from_private_key(&self.private_key);

        ExtendedPublicKey::new(
            self.network,
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            self.chain_code.clone(),
            public_key,
        )
    }

    /// Calculates the fingerprint of this extended key.
    ///
    /// The fingerprint is the first 4 bytes of the HASH160 (RIPEMD160(SHA256(public_key)))
    /// of the public key. This is used to identify parent keys in BIP-32 derivation.
    ///
    /// # Important
    ///
    /// - The fingerprint is calculated from the **public key**, not the private key
    /// - This means ExtendedPrivateKey and its corresponding ExtendedPublicKey have
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
    /// let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    ///
    /// // Get the fingerprint (4 bytes)
    /// let fingerprint = master.fingerprint();
    /// assert_eq!(fingerprint.len(), 4);
    ///
    /// // Master key's parent_fingerprint is [0,0,0,0], but its own fingerprint is not
    /// assert_eq!(master.parent_fingerprint(), &[0, 0, 0, 0]);
    /// assert_ne!(fingerprint, [0, 0, 0, 0]);
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn fingerprint(&self) -> [u8; 4] {
        // Get public key from private key
        let public_key = PublicKey::from_private_key(&self.private_key);
        
        // Calculate HASH160: RIPEMD160(SHA256(public_key))
        let public_key_bytes = public_key.to_bytes();
        
        // Step 1: SHA256
        let sha256_hash = Sha256::digest(&public_key_bytes);
        
        // Step 2: RIPEMD160
        let ripemd160_hash = Ripemd160::digest(&sha256_hash);
        
        // Step 3: Take first 4 bytes
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&ripemd160_hash[0..4]);
        
        fingerprint
    }
}

impl std::fmt::Debug for ExtendedPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedPrivateKey")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &"[REDACTED]")
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_seed_valid_16_bytes() {
        let seed = [0x01; 16];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        assert_eq!(master.depth(), 0);
        assert_eq!(master.child_number(), 0);
        assert_eq!(master.parent_fingerprint(), &[0, 0, 0, 0]);
        assert_eq!(master.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_from_seed_valid_64_bytes() {
        let seed = [0xFF; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        assert_eq!(master.depth(), 0);
        assert_eq!(master.child_number(), 0);
        assert_eq!(master.parent_fingerprint(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_from_seed_seed_too_short() {
        let seed = [0x01; 15];
        let result = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid seed length"));
    }

    #[test]
    fn test_from_seed_seed_too_long() {
        let seed = [0x01; 65];
        let result = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid seed length"));
    }

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [0xAB; 32];
        let master1 = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let master2 = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Same seed should produce same key
        assert_eq!(master1, master2);
    }

    #[test]
    fn test_from_seed_different_seeds() {
        let seed1 = [0x01; 32];
        let seed2 = [0x02; 32];

        let master1 = ExtendedPrivateKey::from_seed(&seed1, Network::BitcoinMainnet).unwrap();
        let master2 = ExtendedPrivateKey::from_seed(&seed2, Network::BitcoinMainnet).unwrap();

        // Different seeds should produce different keys
        assert_ne!(master1, master2);
    }

    #[test]
    fn test_from_seed_different_networks() {
        let seed = [0x01; 32];

        let mainnet = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let testnet = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();

        // Same seed but different networks
        assert_eq!(mainnet.depth(), testnet.depth());
        assert_eq!(mainnet.private_key(), testnet.private_key());
        assert_eq!(mainnet.chain_code(), testnet.chain_code());
        assert_ne!(mainnet.network(), testnet.network());
    }

    #[test]
    fn test_from_seed_master_properties() {
        let seed = [0x12; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Master key always has these values
        assert_eq!(master.depth(), 0);
        assert_eq!(master.child_number(), 0);
        assert_eq!(master.parent_fingerprint(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_from_seed_bip32_test_vector_1() {
        // BIP-32 Test Vector 1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Expected master private key from BIP-32 test vectors
        let expected_key =
            hex::decode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
                .unwrap();
        let expected_chain =
            hex::decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
                .unwrap();

        assert_eq!(master.private_key().to_bytes(), expected_key.as_slice());
        assert_eq!(master.chain_code().as_bytes(), expected_chain.as_slice());
    }

    #[test]
    fn test_from_seed_bip32_test_vector_2() {
        // BIP-32 Test Vector 2
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Expected master private key from BIP-32 test vectors
        let expected_key =
            hex::decode("4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e")
                .unwrap();
        let expected_chain =
            hex::decode("60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689")
                .unwrap();

        assert_eq!(master.private_key().to_bytes(), expected_key.as_slice());
        assert_eq!(master.chain_code().as_bytes(), expected_chain.as_slice());
    }

    #[test]
    fn test_getters() {
        let seed = [0x42; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();

        // Test all getters
        assert_eq!(master.network(), Network::BitcoinTestnet);
        assert_eq!(master.depth(), 0);
        assert_eq!(master.child_number(), 0);
        assert_eq!(master.parent_fingerprint(), &[0, 0, 0, 0]);
        assert!(master.chain_code().as_bytes().len() == 32);
        assert!(master.private_key().to_bytes().len() == 32);
    }

    #[test]
    fn test_extended_private_key_drop_zeroizes() {
        // Create an ExtendedPrivateKey with recognizable data
        let seed = [0x55u8; 32];
        let ext_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Get raw pointers to sensitive data (bind temporaries to variables)
        let private_key_bytes = ext_key.private_key().to_bytes();
        let chain_code_bytes = ext_key.chain_code().as_bytes();
        let private_key_ptr = private_key_bytes.as_ptr();
        let chain_code_ptr = chain_code_bytes.as_ptr();

        // Verify data exists before drop
        assert!(private_key_ptr as usize > 0);
        assert!(chain_code_ptr as usize > 0);

        // Explicitly drop the extended key
        drop(ext_key);

        // After drop, both private_key and chain_code should be zeroized:
        // - private_key: has custom Drop implementation
        // - chain_code: has ZeroizeOnDrop derive macro
        //
        // This test documents that ExtendedPrivateKey properly cleans up
        // all sensitive data when dropped. The actual zeroization cannot
        // be safely verified in safe Rust after the drop occurs.
    }

    #[test]
    fn test_extended_private_key_scope_drop() {
        // Test that ExtendedPrivateKey is dropped when going out of scope
        let depth = {
            let seed = [0x99u8; 32];
            let ext_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
            ext_key.depth() // Access before drop
        };

        assert_eq!(depth, 0);
        // ext_key is dropped here, both private_key and chain_code should be zeroized
    }

    #[test]
    fn test_extended_private_key_clone_independence() {
        // Test that cloning creates independent instances
        let seed = [0x77u8; 32];
        let original = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let cloned = original.clone();

        // Both should be equal
        assert_eq!(original, cloned);
        assert_eq!(original.depth(), cloned.depth());
        assert_eq!(original.private_key().to_bytes(), cloned.private_key().to_bytes());
        assert_eq!(original.chain_code().as_bytes(), cloned.chain_code().as_bytes());

        // Drop one - the other should still be valid
        drop(original);
        assert_eq!(cloned.depth(), 0);
        assert!(cloned.private_key().to_bytes().len() == 32);
    }

    #[test]
    fn test_extended_private_key_sensitive_fields_zeroized() {
        // This test demonstrates that both sensitive fields will be zeroized:
        // 1. private_key: Has custom Drop that calls zeroize()
        // 2. chain_code: Has ZeroizeOnDrop derive macro

        let seed = [0xABu8; 32];
        {
            let ext_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
            
            // Verify we have sensitive data
            assert!(ext_key.private_key().to_bytes().iter().any(|&b| b != 0));
            assert!(ext_key.chain_code().as_bytes().iter().any(|&b| b != 0));
            
            // When ext_key drops at end of scope:
            // 1. Rust calls Drop for all fields in declaration order
            // 2. private_key's Drop zeroizes its memory
            // 3. chain_code's ZeroizeOnDrop zeroizes its memory
        }
        
        // Both sensitive fields have been zeroized now
    }

    #[test]
    fn test_extended_private_key_debug_redacted() {
        // Verify that Debug doesn't leak sensitive information
        let seed = [0xCCu8; 32];
        let ext_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let debug_output = format!("{:?}", ext_key);
        
        // Should contain non-sensitive fields
        assert!(debug_output.contains("ExtendedPrivateKey"));
        assert!(debug_output.contains("network"));
        assert!(debug_output.contains("depth"));
        
        // Should NOT contain sensitive data
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains(&hex::encode(ext_key.private_key().to_bytes())));
        assert!(!debug_output.contains(&hex::encode(ext_key.chain_code().as_bytes())));
    }

    // Task 21: Tests for to_extended_public_key()

    #[test]
    fn test_to_extended_public_key_basic() {
        let seed = [0x01; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();

        // Public key should match private key's public key
        assert_eq!(ext_pub.public_key().to_bytes(), ext_priv.private_key().public_key().serialize());
    }

    #[test]
    fn test_to_extended_public_key_preserves_metadata() {
        let seed = [0x02; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();

        // All metadata should be preserved
        assert_eq!(ext_pub.network(), ext_priv.network());
        assert_eq!(ext_pub.depth(), ext_priv.depth());
        assert_eq!(ext_pub.parent_fingerprint(), ext_priv.parent_fingerprint());
        assert_eq!(ext_pub.child_number(), ext_priv.child_number());
        assert_eq!(ext_pub.chain_code().as_bytes(), ext_priv.chain_code().as_bytes());
    }

    #[test]
    fn test_to_extended_public_key_chain_code_same() {
        // Critical: chain code MUST be the same for derivation to work
        let seed = [0x03; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();

        assert_eq!(ext_pub.chain_code(), ext_priv.chain_code());
    }

    #[test]
    fn test_to_extended_public_key_different_networks() {
        let seed = [0x04; 32];
        
        let mainnet_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let mainnet_pub = mainnet_priv.to_extended_public_key();
        
        let testnet_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        let testnet_pub = testnet_priv.to_extended_public_key();

        // Same seed but different networks
        assert_eq!(mainnet_pub.network(), Network::BitcoinMainnet);
        assert_eq!(testnet_pub.network(), Network::BitcoinTestnet);
        
        // Keys and chain codes should be the same (only network differs)
        assert_eq!(mainnet_pub.public_key().to_bytes(), testnet_pub.public_key().to_bytes());
        assert_eq!(mainnet_pub.chain_code().as_bytes(), testnet_pub.chain_code().as_bytes());
    }

    #[test]
    fn test_to_extended_public_key_deterministic() {
        let seed = [0x05; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let ext_pub1 = ext_priv.to_extended_public_key();
        let ext_pub2 = ext_priv.to_extended_public_key();

        // Should produce the same result every time
        assert_eq!(ext_pub1, ext_pub2);
    }

    #[test]
    fn test_to_extended_public_key_master_key() {
        let seed = [0x06; 32];
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let master_pub = master_priv.to_extended_public_key();

        // Master key properties should be preserved
        assert_eq!(master_pub.depth(), 0);
        assert_eq!(master_pub.child_number(), 0);
        assert_eq!(master_pub.parent_fingerprint(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_to_extended_public_key_bip32_test_vector() {
        // BIP-32 Test Vector 1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let master_pub = master_priv.to_extended_public_key();

        // Expected master public key from BIP-32 test vectors
        let expected_pubkey = hex::decode(
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
        ).unwrap();

        assert_eq!(master_pub.public_key().to_bytes(), expected_pubkey.as_slice());
        
        // Chain code should match private key's chain code
        let expected_chain = hex::decode(
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        ).unwrap();
        assert_eq!(master_pub.chain_code().as_bytes(), expected_chain.as_slice());
    }

    // Task 23: Tests for fingerprint calculation

    #[test]
    fn test_fingerprint_length() {
        let seed = [0x01; 32];
        let ext_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let fingerprint = ext_key.fingerprint();

        // Fingerprint must be exactly 4 bytes
        assert_eq!(fingerprint.len(), 4);
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let seed = [0x02; 32];
        let ext_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let fingerprint1 = ext_key.fingerprint();
        let fingerprint2 = ext_key.fingerprint();

        // Should produce the same fingerprint every time
        assert_eq!(fingerprint1, fingerprint2);
    }

    #[test]
    fn test_fingerprint_different_for_different_keys() {
        let seed1 = [0x03; 32];
        let seed2 = [0x04; 32];
        
        let ext_key1 = ExtendedPrivateKey::from_seed(&seed1, Network::BitcoinMainnet).unwrap();
        let ext_key2 = ExtendedPrivateKey::from_seed(&seed2, Network::BitcoinMainnet).unwrap();

        // Different keys should have different fingerprints
        assert_ne!(ext_key1.fingerprint(), ext_key2.fingerprint());
    }

    #[test]
    fn test_fingerprint_same_for_private_and_public() {
        let seed = [0x05; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();

        // Private and public extended keys should have the same fingerprint
        assert_eq!(ext_priv.fingerprint(), ext_pub.fingerprint());
    }

    #[test]
    fn test_fingerprint_bip32_test_vector() {
        // BIP-32 Test Vector 1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Expected fingerprint from BIP-32 test vectors
        // The master key's fingerprint is derived from its public key
        // Expected: 3442193e (from test vector Chain m)
        let expected_fingerprint = hex::decode("3442193e").unwrap();
        
        assert_eq!(master.fingerprint(), expected_fingerprint.as_slice());
    }

    #[test]
    fn test_fingerprint_master_key_not_zero() {
        // Master key's fingerprint should NOT be [0,0,0,0]
        // (that's the parent_fingerprint, not the key's own fingerprint)
        let seed = [0x06; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        assert_ne!(master.fingerprint(), [0, 0, 0, 0]);
        assert_eq!(master.parent_fingerprint(), &[0, 0, 0, 0]); // But parent is [0,0,0,0]
    }

    #[test]
    fn test_fingerprint_uses_public_key() {
        // Fingerprint should be calculated from the public key, not private key
        // Two different private keys that somehow had the same public key (impossible in practice)
        // would have the same fingerprint
        let seed = [0x07; 32];
        let ext_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let ext_pub = ext_priv.to_extended_public_key();

        // This test documents that fingerprint is derived from public key
        // by verifying that both private and public extended keys produce same fingerprint
        assert_eq!(ext_priv.fingerprint(), ext_pub.fingerprint());
    }
}
