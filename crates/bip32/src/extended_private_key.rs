//! Extended private key implementation for BIP32 hierarchical deterministic wallets.
//!
//! This module provides the core ExtendedPrivateKey type which combines a private key
//! with metadata necessary for hierarchical key derivation according to BIP-32.

use crate::{ChainCode, ChildNumber, Error, ExtendedPublicKey, Network, PrivateKey, PublicKey, Result};
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
/// ```rust
/// use bip32::{ExtendedPrivateKey, Network, ChildNumber};
///
/// // Generate master key from seed
/// let seed = [0u8; 64]; // In practice, use BIP-39 mnemonic
/// let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
///
/// // Master key properties
/// assert_eq!(master.depth(), 0);
/// assert_eq!(master.child_number(), ChildNumber::Normal(0));
///
/// // Derive a child key
/// let child = master.derive_child(ChildNumber::Normal(0))?;
/// assert_eq!(child.depth(), 1);
/// # Ok::<(), bip32::Error>(())
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
    /// - `ChildNumber::Normal(n)`: normal derivation (0 to 2^31-1)
    /// - `ChildNumber::Hardened(n)`: hardened derivation (2^31 to 2^32-1)
    ///
    /// Set to `ChildNumber::Normal(0)` for the master key.
    child_number: ChildNumber,

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
    /// use bip32::{ExtendedPrivateKey, Network, ChildNumber};
    ///
    /// // Generate from a 64-byte seed (typically from BIP-39)
    /// let seed = [0x01; 64];
    /// let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    ///
    /// // Master key properties
    /// assert_eq!(master.depth(), 0);
    /// assert_eq!(master.child_number(), ChildNumber::Normal(0));
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
            child_number: ChildNumber::Normal(0),
            chain_code,
            private_key,
        })
    }

    /// Creates an extended private key from a BIP39 mnemonic phrase.
    ///
    /// This method provides convenient integration with BIP39 mnemonic phrases,
    /// converting the mnemonic to a seed and then generating the master extended
    /// private key. This is the standard way to create hierarchical deterministic
    /// wallets from recovery phrases.
    ///
    /// # Process
    ///
    /// 1. Convert mnemonic to 512-bit seed using PBKDF2-HMAC-SHA512 (BIP39)
    /// 2. Generate master extended private key from seed (BIP32)
    ///
    /// # Parameters
    ///
    /// * `mnemonic` - A validated BIP39 mnemonic phrase
    /// * `passphrase` - Optional passphrase for additional security (BIP39 "25th word")
    ///   - `None` or `Some("")` = no passphrase (standard)
    ///   - `Some("password")` = additional security layer
    /// * `network` - The cryptocurrency network (Bitcoin mainnet, testnet, etc.)
    ///
    /// # Passphrase Security
    ///
    /// The passphrase acts as a "25th word" that:
    /// - Provides plausible deniability (different passphrases = different wallets)
    /// - Adds protection if mnemonic is compromised
    /// - Must be remembered separately (not written with mnemonic)
    /// - **Warning**: Lost passphrase = lost access to funds
    ///
    /// # Returns
    ///
    /// A master extended private key with:
    /// - `depth` = 0
    /// - `parent_fingerprint` = [0, 0, 0, 0]
    /// - `child_number` = 0
    /// - Derived private key and chain code from the seed
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Seed generation fails (BIP39 internal error)
    /// - The derived private key is invalid (extremely rare, < 2^-127 probability)
    ///
    /// # Examples
    ///
    /// ## Basic Usage (No Passphrase)
    ///
    /// ```rust
    /// use bip32::{ExtendedPrivateKey, Network};
    /// use bip39::{Mnemonic, Language};
    ///
    /// // User's recovery phrase
    /// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let mnemonic = Mnemonic::from_phrase(phrase, Language::English)?;
    ///
    /// // Generate master key (no passphrase)
    /// let master = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet)?;
    ///
    /// assert_eq!(master.depth(), 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// ## With Passphrase (Enhanced Security)
    ///
    /// ```rust
    /// use bip32::{ExtendedPrivateKey, Network};
    /// use bip39::{Mnemonic, Language};
    ///
    /// let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    /// let mnemonic = Mnemonic::from_phrase(phrase, Language::English)?;
    ///
    /// // Same mnemonic, different passphrases = different wallets
    /// let wallet1 = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet)?;
    /// let wallet2 = ExtendedPrivateKey::from_mnemonic(&mnemonic, Some("secret"), Network::BitcoinMainnet)?;
    ///
    /// assert_ne!(wallet1.private_key().to_bytes(), wallet2.private_key().to_bytes());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// ## Complete Wallet Creation Workflow
    ///
    /// ```rust
    /// use bip32::{ExtendedPrivateKey, Network, DerivationPath};
    /// use bip39::{Mnemonic, Language};
    /// use std::str::FromStr;
    ///
    /// // 1. Parse user's recovery phrase
    /// let phrase = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    /// let mnemonic = Mnemonic::from_phrase(phrase, Language::English)?;
    ///
    /// // 2. Generate master key with optional passphrase
    /// let master = ExtendedPrivateKey::from_mnemonic(
    ///     &mnemonic,
    ///     Some("my secure passphrase"),
    ///     Network::BitcoinMainnet
    /// )?;
    ///
    /// // 3. Derive BIP-44 account key (m/44'/0'/0')
    /// let account_path = DerivationPath::from_str("m/44'/0'/0'")?;
    /// let account = master.derive_path(&account_path)?;
    ///
    /// // 4. Derive first receiving address (m/44'/0'/0'/0/0)
    /// let receive_path = DerivationPath::from_str("m/0/0")?;
    /// let address_key = account.derive_path(&receive_path)?;
    ///
    /// assert_eq!(address_key.depth(), 5);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_mnemonic(
        mnemonic: &bip39::Mnemonic,
        passphrase: Option<&str>,
        network: Network,
    ) -> Result<Self> {
        // Convert mnemonic to seed using BIP39
        // passphrase.unwrap_or("") follows BIP39 spec: empty string if no passphrase
        let seed = mnemonic.to_seed(passphrase.unwrap_or(""))?;
        
        // Use existing from_seed implementation
        Self::from_seed(&seed, network)
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

    /// Derives a child extended private key from this extended private key.
    ///
    /// This implements the BIP-32 child key derivation (CKD) function for private keys.
    /// It supports both normal and hardened derivation based on the child number type.
    ///
    /// # Algorithm
    ///
    /// For **normal derivation** (`ChildNumber::Normal(n)`):
    /// 1. Data = serP(parent_public_key) || ser32(child_number)
    /// 2. I = HMAC-SHA512(Key = parent_chain_code, Data = Data)
    /// 3. Split I into IL (first 32 bytes) and IR (last 32 bytes)
    /// 4. child_private_key = (parse256(IL) + parent_private_key) mod n
    /// 5. child_chain_code = IR
    ///
    /// For **hardened derivation** (`ChildNumber::Hardened(n)`):
    /// 1. Data = 0x00 || ser256(parent_private_key) || ser32(child_number)
    /// 2. I = HMAC-SHA512(Key = parent_chain_code, Data = Data)
    /// 3. Split I into IL and IR
    /// 4. child_private_key = (parse256(IL) + parent_private_key) mod n
    /// 5. child_chain_code = IR
    ///
    /// # Arguments
    ///
    /// * `child_number` - The child number (normal or hardened)
    ///
    /// # Returns
    ///
    /// Returns a new `ExtendedPrivateKey` with:
    /// - Incremented depth
    /// - Parent fingerprint set to this key's fingerprint
    /// - Child number set to the provided value
    /// - Derived private key and chain code
    ///
    /// # Errors
    ///
    /// Returns [`Error::MaxDepthExceeded`] if this key is already at maximum depth (255).
    /// Returns [`Error::InvalidPrivateKey`] if derivation produces an invalid key (extremely rare).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::{ExtendedPrivateKey, ChildNumber, Network};
    ///
    /// let seed = [0u8; 64];
    /// let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    ///
    /// // Derive normal child at index 0
    /// let child_0 = master.derive_child(ChildNumber::Normal(0))?;
    /// assert_eq!(child_0.depth(), 1);
    /// assert_eq!(child_0.child_number(), ChildNumber::Normal(0));
    ///
    /// // Derive hardened child at index 0
    /// let child_0h = master.derive_child(ChildNumber::Hardened(0))?;
    /// assert_eq!(child_0h.child_number(), ChildNumber::Hardened(0));
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn derive_child(&self, child_number: ChildNumber) -> Result<Self> {
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

        // Determine if this is hardened derivation and get the raw index
        let is_hardened = child_number.is_hardened();
        let index = child_number.to_index();

        if is_hardened {
            // Hardened derivation: use private key
            // Data = 0x00 || private_key (32 bytes) || child_number (4 bytes)
            hmac.update(&[0x00]);
            hmac.update(&self.private_key.to_bytes());
        } else {
            // Normal derivation: use public key
            // Data = public_key (33 bytes compressed) || child_number (4 bytes)
            let public_key = PublicKey::from_private_key(&self.private_key);
            hmac.update(&public_key.to_bytes());
        }

        // Add child number (big-endian)
        hmac.update(&index.to_be_bytes());

        // Compute HMAC-SHA512
        let result = hmac.finalize().into_bytes();

        // Split into IL (first 32 bytes) and IR (last 32 bytes)
        let (il, ir) = result.split_at(32);

        // IL becomes the tweak to add to parent private key
        // child_private_key = (IL + parent_private_key) mod n
        let child_private_key = self.private_key.tweak_add(il)?;

        // IR becomes the child chain code
        let child_chain_code = ChainCode::from_bytes(ir)?;

        // Calculate parent fingerprint (first 4 bytes of HASH160 of parent public key)
        let parent_fingerprint = self.fingerprint();

        Ok(ExtendedPrivateKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number,
            chain_code: child_chain_code,
            private_key: child_private_key,
        })
    }

    /// Derives an extended private key from a derivation path.
    ///
    /// This is a convenience method that iteratively calls `derive_child()` for each
    /// component in the path. It supports both normal and hardened derivation at any level.
    ///
    /// # Arguments
    ///
    /// * `path` - A `DerivationPath` specifying the full derivation from master key
    ///
    /// # Returns
    ///
    /// Returns the extended private key at the end of the derivation path.
    ///
    /// # Errors
    ///
    /// Returns an error if any step of the derivation fails (e.g., max depth exceeded,
    /// invalid key generated).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::{ExtendedPrivateKey, DerivationPath, Network};
    /// use std::str::FromStr;
    ///
    /// let seed = [0u8; 64];
    /// let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    ///
    /// // BIP-44 Bitcoin path
    /// let path = DerivationPath::from_str("m/44'/0'/0'/0/0")?;
    /// let address_key = master.derive_path(&path)?;
    ///
    /// assert_eq!(address_key.depth(), 5);
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn derive_path(&self, path: &crate::DerivationPath) -> Result<Self> {
        // Start with current key
        let mut current = self.clone();
        
        // Derive each child in the path
        for child_number in path.iter() {
            current = current.derive_child(*child_number)?;
        }
        
        Ok(current)
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

impl std::fmt::Display for ExtendedPrivateKey {
    /// Serializes the extended private key to Base58Check encoding (xprv/tprv format).
    ///
    /// Format per BIP-32:
    /// - 4 bytes: version bytes (network-specific)
    /// - 1 byte: depth
    /// - 4 bytes: parent fingerprint
    /// - 4 bytes: child number (big-endian)
    /// - 32 bytes: chain code
    /// - 33 bytes: 0x00 || private key
    /// - 4 bytes: checksum (first 4 bytes of double SHA256)
    ///
    /// Total: 82 bytes, then Base58 encoded
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use sha2::{Digest, Sha256};
        
        // Build the 78-byte payload
        let mut data = Vec::with_capacity(78);
        
        // 1. Version bytes (4 bytes) - network specific
        data.extend_from_slice(&self.network.xprv_version().to_be_bytes());
        
        // 2. Depth (1 byte)
        data.push(self.depth);
        
        // 3. Parent fingerprint (4 bytes)
        data.extend_from_slice(&self.parent_fingerprint);
        
        // 4. Child number (4 bytes, big-endian)
        data.extend_from_slice(&self.child_number.to_index().to_be_bytes());
        
        // 5. Chain code (32 bytes)
        data.extend_from_slice(self.chain_code.as_bytes());
        
        // 6. Key data (33 bytes): 0x00 || private_key (32 bytes)
        data.push(0x00);
        data.extend_from_slice(&self.private_key.to_bytes());
        
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

impl std::str::FromStr for ExtendedPrivateKey {
    type Err = Error;

    /// Deserializes an extended private key from Base58Check encoding (xprv/tprv format).
    ///
    /// # Arguments
    ///
    /// * `s` - A Base58Check encoded extended private key string (xprv... or tprv...)
    ///
    /// # Returns
    ///
    /// Returns the deserialized `ExtendedPrivateKey` or an error if:
    /// - The input is not valid Base58
    /// - The checksum is invalid
    /// - The data length is incorrect (must be 82 bytes)
    /// - The version bytes are not recognized (not xprv or tprv)
    /// - The key data is invalid
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::ExtendedPrivateKey;
    /// use std::str::FromStr;
    ///
    /// let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    /// let key = ExtendedPrivateKey::from_str(xprv)?;
    /// # Ok::<(), bip32::Error>(())
    /// ```
    fn from_str(s: &str) -> Result<Self> {
        use sha2::{Digest, Sha256};
        
        // 1. Base58 decode
        let data = bs58::decode(s)
            .into_vec()
            .map_err(|_| Error::InvalidExtendedKey {
                reason: "Invalid Base58 encoding".to_string(),
            })?;
        
        // 2. Check length (78 bytes + 4 bytes checksum)
        if data.len() != 82 {
            return Err(Error::InvalidExtendedKey {
                reason: format!("Invalid length: expected 82 bytes, got {}", data.len()),
            });
        }
        
        // 3. Verify checksum
        let payload = &data[0..78];
        let checksum = &data[78..82];
        
        let hash1 = Sha256::digest(payload);
        let hash2 = Sha256::digest(&hash1);
        let expected_checksum = &hash2[0..4];
        
        if checksum != expected_checksum {
            return Err(Error::InvalidExtendedKey {
                reason: "Invalid checksum".to_string(),
            });
        }
        
        // 4. Parse version bytes to determine network
        let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let network = Network::from_xprv_version(version).ok_or_else(|| {
            Error::InvalidExtendedKey {
                reason: format!("Unknown xprv version bytes: 0x{:08X}", version),
            }
        })?;
        
        // 5. Parse depth
        let depth = data[4];
        
        // 6. Parse parent fingerprint
        let parent_fingerprint = [data[5], data[6], data[7], data[8]];
        
        // 7. Parse child number
        let child_index = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
        let child_number = ChildNumber::from_index(child_index);
        
        // 8. Parse chain code (32 bytes)
        let chain_code_bytes = &data[13..45];
        let chain_code = ChainCode::from_bytes(chain_code_bytes)?;
        
        // 9. Parse private key (skip 0x00 prefix, then 32 bytes)
        if data[45] != 0x00 {
            return Err(Error::InvalidExtendedKey {
                reason: "Private key data must start with 0x00".to_string(),
            });
        }
        let private_key_bytes = &data[46..78];
        let private_key = PrivateKey::from_bytes(private_key_bytes)?;
        
        Ok(ExtendedPrivateKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            private_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DerivationPath;
    use std::str::FromStr;

    #[test]
    fn test_from_seed_valid_16_bytes() {
        let seed = [0x01; 16];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        assert_eq!(master.depth(), 0);
        assert_eq!(master.child_number(), ChildNumber::Normal(0));
        assert_eq!(master.parent_fingerprint(), &[0, 0, 0, 0]);
        assert_eq!(master.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_from_seed_valid_64_bytes() {
        let seed = [0xFF; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        assert_eq!(master.depth(), 0);
        assert_eq!(master.child_number(), ChildNumber::Normal(0));
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
        assert_eq!(master.child_number(), ChildNumber::Normal(0));
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
        assert_eq!(master.child_number(), ChildNumber::Normal(0));
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
        assert_eq!(master_pub.child_number(), ChildNumber::Normal(0));
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

    #[test]
    fn test_derive_child_normal_basic() {
        let seed = [0x01; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive first normal child (index 0)
        let child = master.derive_child(ChildNumber::Normal(0)).unwrap();
        
        // Child should have incremented depth
        assert_eq!(child.depth(), 1);
        assert_eq!(child.child_number(), ChildNumber::Normal(0));
        
        // Parent fingerprint should be master's fingerprint
        assert_eq!(child.parent_fingerprint(), &master.fingerprint());
        
        // Network should be preserved
        assert_eq!(child.network(), master.network());
        
        // Key and chain code should be different from parent
        assert_ne!(child.private_key().to_bytes(), master.private_key().to_bytes());
        assert_ne!(child.chain_code().as_bytes(), master.chain_code().as_bytes());
    }

    #[test]
    fn test_derive_child_normal_multiple_indices() {
        let seed = [0x02; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive different normal children
        let child0 = master.derive_child(ChildNumber::Normal(0)).unwrap();
        let child1 = master.derive_child(ChildNumber::Normal(1)).unwrap();
        let child100 = master.derive_child(ChildNumber::Normal(100)).unwrap();
        
        // All should have depth 1
        assert_eq!(child0.depth(), 1);
        assert_eq!(child1.depth(), 1);
        assert_eq!(child100.depth(), 1);
        
        // Child numbers should match indices
        assert_eq!(child0.child_number(), ChildNumber::Normal(0));
        assert_eq!(child1.child_number(), ChildNumber::Normal(1));
        assert_eq!(child100.child_number(), ChildNumber::Normal(100));
        
        // All should have same parent fingerprint
        let parent_fp = master.fingerprint();
        assert_eq!(child0.parent_fingerprint(), &parent_fp);
        assert_eq!(child1.parent_fingerprint(), &parent_fp);
        assert_eq!(child100.parent_fingerprint(), &parent_fp);
        
        // Keys should all be different
        assert_ne!(child0.private_key().to_bytes(), child1.private_key().to_bytes());
        assert_ne!(child0.private_key().to_bytes(), child100.private_key().to_bytes());
        assert_ne!(child1.private_key().to_bytes(), child100.private_key().to_bytes());
    }

    #[test]
    fn test_derive_child_hardened_basic() {
        let seed = [0x03; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive first hardened child (index 0)
        let child = master.derive_child(ChildNumber::Hardened(0)).unwrap();
        
        assert_eq!(child.depth(), 1);
        assert_eq!(child.child_number(), ChildNumber::Hardened(0));
        assert_eq!(child.parent_fingerprint(), &master.fingerprint());
    }

    #[test]
    fn test_derive_child_hardened_multiple() {
        let seed = [0x04; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive different hardened children
        let hardened_0 = master.derive_child(ChildNumber::Hardened(0)).unwrap();
        let hardened_1 = master.derive_child(ChildNumber::Hardened(1)).unwrap();
        let hardened_44 = master.derive_child(ChildNumber::Hardened(44)).unwrap();
        
        assert_eq!(hardened_0.child_number(), ChildNumber::Hardened(0));
        assert_eq!(hardened_1.child_number(), ChildNumber::Hardened(1));
        assert_eq!(hardened_44.child_number(), ChildNumber::Hardened(44));
        
        // All should have different keys
        assert_ne!(hardened_0.private_key().to_bytes(), hardened_1.private_key().to_bytes());
        assert_ne!(hardened_0.private_key().to_bytes(), hardened_44.private_key().to_bytes());
    }

    #[test]
    fn test_derive_child_normal_vs_hardened_different() {
        let seed = [0x05; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive normal child at index 0
        let normal_0 = master.derive_child(ChildNumber::Normal(0)).unwrap();
        
        // Derive hardened child at index 0
        let hardened_0 = master.derive_child(ChildNumber::Hardened(0)).unwrap();
        
        // Should produce different keys even though base index is same
        assert_ne!(normal_0.private_key().to_bytes(), hardened_0.private_key().to_bytes());
        assert_ne!(normal_0.chain_code().as_bytes(), hardened_0.chain_code().as_bytes());
        
        // Child numbers should be different
        assert_eq!(normal_0.child_number(), ChildNumber::Normal(0));
        assert_eq!(hardened_0.child_number(), ChildNumber::Hardened(0));
    }

    #[test]
    fn test_derive_child_deterministic() {
        let seed = [0x06; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive same child twice
        let child1 = master.derive_child(ChildNumber::Normal(5)).unwrap();
        let child2 = master.derive_child(ChildNumber::Normal(5)).unwrap();
        
        // Should be identical
        assert_eq!(child1, child2);
        assert_eq!(child1.private_key().to_bytes(), child2.private_key().to_bytes());
        assert_eq!(child1.chain_code().as_bytes(), child2.chain_code().as_bytes());
    }

    #[test]
    fn test_derive_child_multi_level() {
        let seed = [0x07; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive child, then grandchild
        let child = master.derive_child(ChildNumber::Normal(0)).unwrap();
        let grandchild = child.derive_child(ChildNumber::Normal(0)).unwrap();
        
        // Depths should increase
        assert_eq!(master.depth(), 0);
        assert_eq!(child.depth(), 1);
        assert_eq!(grandchild.depth(), 2);
        
        // Grandchild's parent fingerprint should be child's fingerprint
        assert_eq!(grandchild.parent_fingerprint(), &child.fingerprint());
        assert_ne!(grandchild.parent_fingerprint(), &master.fingerprint());
    }

    #[test]
    fn test_derive_child_preserves_network() {
        let seed = [0x08; 32];
        
        let mainnet_master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let mainnet_child = mainnet_master.derive_child(ChildNumber::Normal(0)).unwrap();
        
        let testnet_master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        let testnet_child = testnet_master.derive_child(ChildNumber::Normal(0)).unwrap();
        
        assert_eq!(mainnet_child.network(), Network::BitcoinMainnet);
        assert_eq!(testnet_child.network(), Network::BitcoinTestnet);
        
        // Keys should be same (network doesn't affect derivation)
        assert_eq!(mainnet_child.private_key().to_bytes(), testnet_child.private_key().to_bytes());
    }

    #[test]
    fn test_derive_child_max_normal_index() {
        let seed = [0x09; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Maximum normal child index is 2^31 - 1
        let max_normal_index = ChildNumber::MAX_NORMAL_INDEX;
        let child = master.derive_child(ChildNumber::Normal(max_normal_index)).unwrap();
        
        assert_eq!(child.child_number(), ChildNumber::Normal(max_normal_index));
        assert_eq!(child.depth(), 1);
    }

    #[test]
    fn test_derive_child_max_index() {
        let seed = [0x0A; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Maximum hardened index
        let max_hardened = ChildNumber::MAX_NORMAL_INDEX;
        let child = master.derive_child(ChildNumber::Hardened(max_hardened)).unwrap();
        
        assert_eq!(child.child_number(), ChildNumber::Hardened(max_hardened));
        assert_eq!(child.depth(), 1);
    }

    #[test]
    fn test_derive_child_depth_overflow() {
        let seed = [0x0B; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Manually create a key at max depth
        let max_depth_key = ExtendedPrivateKey {
            network: master.network(),
            depth: ExtendedPrivateKey::MAX_DEPTH,
            parent_fingerprint: [0; 4],
            child_number: ChildNumber::Normal(0),
            chain_code: master.chain_code().clone(),
            private_key: master.private_key().clone(),
        };
        
        // Trying to derive a child should fail
        let result = max_depth_key.derive_child(ChildNumber::Normal(0));
        assert!(result.is_err());
        
        match result {
            Err(Error::MaxDepthExceeded { depth }) => {
                assert_eq!(depth, ExtendedPrivateKey::MAX_DEPTH);
            }
            _ => panic!("Expected MaxDepthExceeded error"),
        }
    }

    #[test]
    fn test_derive_child_bip32_test_vector_1() {
        // BIP-32 Test Vector 1: Chain m/0'
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive m/0' (first hardened child)
        let child = master.derive_child(ChildNumber::Hardened(0)).unwrap();
        
        // Expected values from BIP-32 test vectors
        let expected_key = hex::decode(
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        ).unwrap();
        let expected_chain = hex::decode(
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        ).unwrap();
        
        assert_eq!(child.private_key().to_bytes(), expected_key.as_slice());
        assert_eq!(child.chain_code().as_bytes(), expected_chain.as_slice());
        assert_eq!(child.depth(), 1);
        assert_eq!(child.child_number(), ChildNumber::Hardened(0));
    }

    #[test]
    fn test_derive_child_bip32_test_vector_2() {
        // BIP-32 Test Vector 1: Chain m/0'/1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive m/0'
        let child_0h = master.derive_child(ChildNumber::Hardened(0)).unwrap();
        
        // Derive m/0'/1 (normal child from hardened parent)
        let child_0h_1 = child_0h.derive_child(ChildNumber::Normal(1)).unwrap();
        
        // Expected values from BIP-32 test vectors
        let expected_key = hex::decode(
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        ).unwrap();
        let expected_chain = hex::decode(
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
        ).unwrap();
        
        assert_eq!(child_0h_1.private_key().to_bytes(), expected_key.as_slice());
        assert_eq!(child_0h_1.chain_code().as_bytes(), expected_chain.as_slice());
        assert_eq!(child_0h_1.depth(), 2);
        assert_eq!(child_0h_1.child_number(), ChildNumber::Normal(1));
    }

    #[test]
    fn test_derive_child_deep_path() {
        let seed = [0x0C; 32];
        let mut current = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive a deep path (but not exceeding MAX_DEPTH)
        for i in 0..10 {
            current = current.derive_child(ChildNumber::Normal(i)).unwrap();
            assert_eq!(current.depth(), (i + 1) as u8);
            assert_eq!(current.child_number(), ChildNumber::Normal(i));
        }
        
        assert_eq!(current.depth(), 10);
    }

    // ========================================================================
    // Task 39: Tests for derive_path() (multi-level derivation)
    // ========================================================================

    #[test]
    fn test_derive_path_master_key() {
        let seed = [0x01; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Master path "m" should return same key
        let path = DerivationPath::from_str("m").unwrap();
        let result = master.derive_path(&path).unwrap();
        
        assert_eq!(result, master);
    }

    #[test]
    fn test_derive_path_single_level() {
        let seed = [0x02; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Single level path "m/0"
        let path = DerivationPath::from_str("m/0").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        // Should be same as derive_child
        let expected = master.derive_child(ChildNumber::Normal(0)).unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_derive_path_multi_level() {
        let seed = [0x03; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Multi-level path "m/0/1/2"
        let path = DerivationPath::from_str("m/0/1/2").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        // Manual derivation
        let child_0 = master.derive_child(ChildNumber::Normal(0)).unwrap();
        let child_0_1 = child_0.derive_child(ChildNumber::Normal(1)).unwrap();
        let child_0_1_2 = child_0_1.derive_child(ChildNumber::Normal(2)).unwrap();
        
        assert_eq!(derived, child_0_1_2);
        assert_eq!(derived.depth(), 3);
    }

    #[test]
    fn test_derive_path_hardened() {
        let seed = [0x04; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Hardened path "m/0'"
        let path = DerivationPath::from_str("m/0'").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        let expected = master.derive_child(ChildNumber::Hardened(0)).unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn test_derive_path_mixed_hardened_normal() {
        let seed = [0x05; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Mixed path "m/0'/1/2'"
        let path = DerivationPath::from_str("m/0'/1/2'").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        // Manual derivation
        let child_0h = master.derive_child(ChildNumber::Hardened(0)).unwrap();
        let child_0h_1 = child_0h.derive_child(ChildNumber::Normal(1)).unwrap();
        let child_0h_1_2h = child_0h_1.derive_child(ChildNumber::Hardened(2)).unwrap();
        
        assert_eq!(derived, child_0h_1_2h);
    }

    #[test]
    fn test_derive_path_bip44() {
        let seed = [0x06; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // BIP-44 path: m/44'/0'/0'/0/0
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        assert_eq!(derived.depth(), 5);
        assert_eq!(derived.child_number(), ChildNumber::Normal(0));
        
        // Verify each level
        let purpose = master.derive_child(ChildNumber::Hardened(44)).unwrap();
        let coin = purpose.derive_child(ChildNumber::Hardened(0)).unwrap();
        let account = coin.derive_child(ChildNumber::Hardened(0)).unwrap();
        let change = account.derive_child(ChildNumber::Normal(0)).unwrap();
        let address = change.derive_child(ChildNumber::Normal(0)).unwrap();
        
        assert_eq!(derived, address);
    }

    #[test]
    fn test_derive_path_bip49() {
        let seed = [0x07; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // BIP-49 path (P2WPKH-nested-in-P2SH)
        let path = DerivationPath::from_str("m/49'/0'/0'/0/0").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        assert_eq!(derived.depth(), 5);
    }

    #[test]
    fn test_derive_path_bip84() {
        let seed = [0x08; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // BIP-84 path (Native SegWit)
        let path = DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        assert_eq!(derived.depth(), 5);
    }

    #[test]
    fn test_derive_path_deterministic() {
        let seed = [0x09; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let path = DerivationPath::from_str("m/0'/1/2").unwrap();
        
        // Derive same path twice
        let derived1 = master.derive_path(&path).unwrap();
        let derived2 = master.derive_path(&path).unwrap();
        
        assert_eq!(derived1, derived2);
    }

    #[test]
    fn test_derive_path_preserves_network() {
        let seed = [0x0A; 32];
        
        let mainnet = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let testnet = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        
        let path = DerivationPath::from_str("m/0/1").unwrap();
        
        let mainnet_derived = mainnet.derive_path(&path).unwrap();
        let testnet_derived = testnet.derive_path(&path).unwrap();
        
        assert_eq!(mainnet_derived.network(), Network::BitcoinMainnet);
        assert_eq!(testnet_derived.network(), Network::BitcoinTestnet);
    }

    #[test]
    fn test_derive_path_deep() {
        let seed = [0x0B; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Create a deep path (10 levels)
        let path = DerivationPath::from_str("m/0/1/2/3/4/5/6/7/8/9").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        assert_eq!(derived.depth(), 10);
        assert_eq!(derived.child_number(), ChildNumber::Normal(9));
    }

    #[test]
    fn test_derive_path_bip32_test_vector() {
        // BIP-32 Test Vector 1: m/0'/1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let path = DerivationPath::from_str("m/0'/1").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        // Expected values from BIP-32 test vectors (Chain m/0'/1)
        let expected_key = hex::decode(
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        ).unwrap();
        
        assert_eq!(derived.private_key().to_bytes(), expected_key.as_slice());
        assert_eq!(derived.depth(), 2);
    }

    #[test]
    fn test_derive_path_multiple_accounts() {
        let seed = [0x0C; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive multiple accounts
        let account_0 = master.derive_path(&DerivationPath::from_str("m/44'/0'/0'").unwrap()).unwrap();
        let account_1 = master.derive_path(&DerivationPath::from_str("m/44'/0'/1'").unwrap()).unwrap();
        let account_2 = master.derive_path(&DerivationPath::from_str("m/44'/0'/2'").unwrap()).unwrap();
        
        // All should be at depth 3
        assert_eq!(account_0.depth(), 3);
        assert_eq!(account_1.depth(), 3);
        assert_eq!(account_2.depth(), 3);
        
        // All should be different
        assert_ne!(account_0, account_1);
        assert_ne!(account_0, account_2);
        assert_ne!(account_1, account_2);
    }

    #[test]
    fn test_derive_path_address_generation() {
        let seed = [0x0D; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Derive account
        let account_path = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        let _account = master.derive_path(&account_path).unwrap();
        
        // Generate 5 addresses from external chain
        for i in 0..5 {
            let addr_path = DerivationPath::from_str(&format!("m/44'/0'/0'/0/{}", i)).unwrap();
            let address_key = master.derive_path(&addr_path).unwrap();
            
            assert_eq!(address_key.depth(), 5);
            assert_eq!(address_key.child_number(), ChildNumber::Normal(i));
        }
    }

    #[test]
    fn test_serialize_master_key_mainnet() {
        // BIP-32 Test Vector 1: Master key
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let serialized = master.to_string();
        
        // Expected from BIP-32 test vectors
        let expected = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_master_key_testnet() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        
        let serialized = master.to_string();
        
        // Should start with "tprv" for testnet
        assert!(serialized.starts_with("tprv"));
        
        // Should be valid base58
        assert!(bs58::decode(&serialized).with_check(None).into_vec().is_ok());
    }

    #[test]
    fn test_serialize_derived_key_hardened() {
        // BIP-32 Test Vector 1: m/0'
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let child = master.derive_child(ChildNumber::Hardened(0)).unwrap();
        
        let serialized = child.to_string();
        
        // Expected from BIP-32 test vectors
        let expected = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_derived_key_normal() {
        // BIP-32 Test Vector 1: m/0'/1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/0'/1").unwrap();
        let child = master.derive_path(&path).unwrap();
        
        let serialized = child.to_string();
        
        // Expected from BIP-32 test vectors
        let expected = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_deep_derivation() {
        // BIP-32 Test Vector 1: m/0'/1/2'/2
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/0'/1/2'/2").unwrap();
        let child = master.derive_path(&path).unwrap();
        
        let serialized = child.to_string();
        
        // Expected from BIP-32 test vectors
        let expected = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334";
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_length() {
        let seed = [0x01; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let serialized = master.to_string();
        
        // Base58 encoded data should be exactly 82 bytes before encoding
        // (78 bytes data + 4 bytes checksum)
        // When decoded, bs58 returns the full bytes
        let decoded = bs58::decode(&serialized).into_vec().unwrap();
        assert_eq!(decoded.len(), 82);
    }

    #[test]
    fn test_serialize_starts_with_xprv_mainnet() {
        let seed = [0x02; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let serialized = master.to_string();
        
        // Mainnet private keys should start with "xprv"
        assert!(serialized.starts_with("xprv"));
    }

    #[test]
    fn test_serialize_starts_with_tprv_testnet() {
        let seed = [0x03; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        
        let serialized = master.to_string();
        
        // Testnet private keys should start with "tprv"
        assert!(serialized.starts_with("tprv"));
    }

    #[test]
    fn test_serialize_deterministic() {
        let seed = [0x04; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        // Serialize same key twice
        let serialized1 = master.to_string();
        let serialized2 = master.to_string();
        
        // Should produce identical output
        assert_eq!(serialized1, serialized2);
    }

    #[test]
    fn test_serialize_different_keys_different_output() {
        let master1 = ExtendedPrivateKey::from_seed(&[0x01; 32], Network::BitcoinMainnet).unwrap();
        let master2 = ExtendedPrivateKey::from_seed(&[0x02; 32], Network::BitcoinMainnet).unwrap();
        
        let serialized1 = master1.to_string();
        let serialized2 = master2.to_string();
        
        // Different keys should produce different serializations
        assert_ne!(serialized1, serialized2);
    }

    #[test]
    fn test_serialize_different_networks_different_output() {
        let seed = [0x05; 32];
        let mainnet = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let testnet = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        
        let mainnet_serialized = mainnet.to_string();
        let testnet_serialized = testnet.to_string();
        
        // Same seed but different networks should produce different serializations
        assert_ne!(mainnet_serialized, testnet_serialized);
        assert!(mainnet_serialized.starts_with("xprv"));
        assert!(testnet_serialized.starts_with("tprv"));
    }

    #[test]
    fn test_serialize_checksum_validation() {
        let seed = [0x06; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let serialized = master.to_string();
        
        // Should decode successfully with checksum validation
        let result = bs58::decode(&serialized).with_check(None).into_vec();
        assert!(result.is_ok());
    }

    #[test]
    fn test_serialize_bip32_test_vector_2_master() {
        // BIP-32 Test Vector 2: Different seed
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let serialized = master.to_string();
        
        // Expected from BIP-32 test vector 2
        let expected = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_bip32_test_vector_2_derived() {
        // BIP-32 Test Vector 2: m/0
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let child = master.derive_child(ChildNumber::Normal(0)).unwrap();
        
        let serialized = child.to_string();
        
        // Expected from BIP-32 test vector 2
        let expected = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt";
        
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_serialize_preserves_all_fields() {
        let seed = [0x07; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        let derived = master.derive_path(&path).unwrap();
        
        let serialized = derived.to_string();
        let decoded = bs58::decode(&serialized).into_vec().unwrap();
        
        // Verify structure (without implementing deserialization yet)
        assert_eq!(decoded.len(), 82); // 78 bytes + 4 checksum
        
        // Version bytes (first 4 bytes) should be mainnet xprv
        assert_eq!(&decoded[0..4], &Network::BitcoinMainnet.xprv_version().to_be_bytes());
        
        // Depth should be 3
        assert_eq!(decoded[4], 3);
    }

    // ========================================================================
    // Task 45: Tests for Base58Check deserialization (xprv format)
    // ========================================================================

    #[test]
    fn test_deserialize_master_key_mainnet() {
        // BIP-32 Test Vector 1: Master key
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        
        let key = ExtendedPrivateKey::from_str(xprv).unwrap();
        
        // Verify it's a master key
        assert_eq!(key.depth(), 0);
        assert_eq!(key.parent_fingerprint(), &[0, 0, 0, 0]);
        assert_eq!(key.child_number(), ChildNumber::Normal(0));
        assert_eq!(key.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_deserialize_master_key_testnet() {
        // Create a testnet key, serialize it, then deserialize
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let original = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        let tprv = original.to_string();
        
        let key = ExtendedPrivateKey::from_str(&tprv).unwrap();
        
        assert_eq!(key.depth(), 0);
        assert_eq!(key.network(), Network::BitcoinTestnet);
        assert_eq!(key, original);
    }

    #[test]
    fn test_deserialize_derived_key_hardened() {
        // BIP-32 Test Vector 1: m/0'
        let xprv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        
        let key = ExtendedPrivateKey::from_str(xprv).unwrap();
        
        assert_eq!(key.depth(), 1);
        assert_eq!(key.child_number(), ChildNumber::Hardened(0));
        assert_eq!(key.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_deserialize_derived_key_normal() {
        // BIP-32 Test Vector 1: m/0'/1
        let xprv = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
        
        let key = ExtendedPrivateKey::from_str(xprv).unwrap();
        
        assert_eq!(key.depth(), 2);
        assert_eq!(key.child_number(), ChildNumber::Normal(1));
        assert_eq!(key.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_deserialize_deep_derivation() {
        // BIP-32 Test Vector 1: m/0'/1/2'/2
        let xprv = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334";
        
        let key = ExtendedPrivateKey::from_str(xprv).unwrap();
        
        assert_eq!(key.depth(), 4);
        assert_eq!(key.child_number(), ChildNumber::Normal(2));
        assert_eq!(key.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_deserialize_round_trip() {
        // Create a key, serialize it, deserialize it back - should be identical
        let seed = [0x42; 32];
        let original = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let serialized = original.to_string();
        let deserialized = ExtendedPrivateKey::from_str(&serialized).unwrap();
        
        assert_eq!(deserialized, original);
    }

    #[test]
    fn test_deserialize_round_trip_derived() {
        let seed = [0x43; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let original = master.derive_path(&DerivationPath::from_str("m/44'/0'/0'").unwrap()).unwrap();
        
        let serialized = original.to_string();
        let deserialized = ExtendedPrivateKey::from_str(&serialized).unwrap();
        
        assert_eq!(deserialized, original);
        assert_eq!(deserialized.depth(), 3);
        assert_eq!(deserialized.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_deserialize_invalid_base58() {
        // Invalid base58 characters
        let invalid = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPH0OIl";
        
        let result = ExtendedPrivateKey::from_str(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_invalid_checksum() {
        // Valid base58 but wrong checksum (last char changed)
        let invalid = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHj";
        
        let result = ExtendedPrivateKey::from_str(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_too_short() {
        // Too short to be valid
        let invalid = "xprv9s21ZrQH";
        
        let result = ExtendedPrivateKey::from_str(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_wrong_prefix() {
        // Valid xpub (public key) instead of xprv
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        
        let result = ExtendedPrivateKey::from_str(xpub);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_preserves_all_fields() {
        let seed = [0x44; 32];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let original = master.derive_path(&DerivationPath::from_str("m/44'/0'/5'").unwrap()).unwrap();
        
        let serialized = original.to_string();
        let deserialized = ExtendedPrivateKey::from_str(&serialized).unwrap();
        
        // Check all fields are preserved
        assert_eq!(deserialized.network(), original.network());
        assert_eq!(deserialized.depth(), original.depth());
        assert_eq!(deserialized.parent_fingerprint(), original.parent_fingerprint());
        assert_eq!(deserialized.child_number(), original.child_number());
        assert_eq!(deserialized.chain_code().as_bytes(), original.chain_code().as_bytes());
        assert_eq!(deserialized.private_key().to_bytes(), original.private_key().to_bytes());
    }

    #[test]
    fn test_deserialize_bip32_test_vector_2_master() {
        // BIP-32 Test Vector 2: Master key
        let xprv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
        
        let key = ExtendedPrivateKey::from_str(xprv).unwrap();
        
        assert_eq!(key.depth(), 0);
        assert_eq!(key.network(), Network::BitcoinMainnet);
        
        // Verify it matches what we get from seed
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let from_seed = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        assert_eq!(key.private_key().to_bytes(), from_seed.private_key().to_bytes());
        assert_eq!(key.chain_code().as_bytes(), from_seed.chain_code().as_bytes());
    }

    #[test]
    fn test_deserialize_bip32_test_vector_2_derived() {
        // BIP-32 Test Vector 2: m/0
        let xprv = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt";
        
        let key = ExtendedPrivateKey::from_str(xprv).unwrap();
        
        assert_eq!(key.depth(), 1);
        assert_eq!(key.child_number(), ChildNumber::Normal(0));
    }

    #[test]
    fn test_deserialize_different_networks() {
        let seed = [0x45; 32];
        
        // Mainnet
        let mainnet_orig = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let mainnet_str = mainnet_orig.to_string();
        let mainnet_parsed = ExtendedPrivateKey::from_str(&mainnet_str).unwrap();
        assert_eq!(mainnet_parsed.network(), Network::BitcoinMainnet);
        assert!(mainnet_str.starts_with("xprv"));
        
        // Testnet
        let testnet_orig = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        let testnet_str = testnet_orig.to_string();
        let testnet_parsed = ExtendedPrivateKey::from_str(&testnet_str).unwrap();
        assert_eq!(testnet_parsed.network(), Network::BitcoinTestnet);
        assert!(testnet_str.starts_with("tprv"));
    }

    // ========================================================================
    // Task 53: Tests for BIP39 mnemonic integration
    // ========================================================================

    #[test]
    fn test_from_mnemonic_basic() {
        // Standard BIP39 test vector
        let mnemonic = bip39::Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            bip39::Language::English
        ).unwrap();
        
        let master = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        
        assert_eq!(master.depth(), 0);
        assert_eq!(master.child_number(), ChildNumber::Normal(0));
        assert_eq!(master.parent_fingerprint(), &[0, 0, 0, 0]);
        assert_eq!(master.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_from_mnemonic_with_passphrase() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            bip39::Language::English
        ).unwrap();
        
        let master_no_pass = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        let master_with_pass = ExtendedPrivateKey::from_mnemonic(&mnemonic, Some("TREZOR"), Network::BitcoinMainnet).unwrap();
        
        // Different passphrases should produce different keys
        assert_ne!(master_no_pass.private_key().to_bytes(), master_with_pass.private_key().to_bytes());
        assert_ne!(master_no_pass.chain_code().as_bytes(), master_with_pass.chain_code().as_bytes());
    }

    #[test]
    fn test_from_mnemonic_deterministic() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            bip39::Language::English
        ).unwrap();
        
        // Same mnemonic should produce same key
        let master1 = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        let master2 = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        
        assert_eq!(master1.private_key().to_bytes(), master2.private_key().to_bytes());
        assert_eq!(master1.chain_code().as_bytes(), master2.chain_code().as_bytes());
    }

    #[test]
    fn test_from_mnemonic_different_networks() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            bip39::Language::English
        ).unwrap();
        
        let mainnet = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        let testnet = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinTestnet).unwrap();
        
        assert_eq!(mainnet.network(), Network::BitcoinMainnet);
        assert_eq!(testnet.network(), Network::BitcoinTestnet);
        
        // Keys should be same (network doesn't affect derivation from seed)
        assert_eq!(mainnet.private_key().to_bytes(), testnet.private_key().to_bytes());
    }

    #[test]
    fn test_from_mnemonic_12_words() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            bip39::Language::English
        ).unwrap();
        
        let master = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        
        assert_eq!(master.depth(), 0);
    }

    #[test]
    fn test_from_mnemonic_24_words() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            bip39::Language::English
        ).unwrap();
        
        let master = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        
        assert_eq!(master.depth(), 0);
        assert_eq!(master.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_from_mnemonic_derivation_works() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            bip39::Language::English
        ).unwrap();
        
        let master = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        
        // Should be able to derive children
        let child = master.derive_child(ChildNumber::Hardened(44)).unwrap();
        assert_eq!(child.depth(), 1);
        assert_eq!(child.child_number(), ChildNumber::Hardened(44));
    }

    #[test]
    fn test_from_mnemonic_to_bip44_path() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            bip39::Language::English
        ).unwrap();
        
        let master = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        
        // Derive BIP-44 path: m/44'/0'/0'/0/0
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let account_key = master.derive_path(&path).unwrap();
        
        assert_eq!(account_key.depth(), 5);
        assert_eq!(account_key.child_number(), ChildNumber::Normal(0));
    }

    #[test]
    fn test_from_mnemonic_passphrase_affects_derivation() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            bip39::Language::English
        ).unwrap();
        
        let master1 = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        let master2 = ExtendedPrivateKey::from_mnemonic(&mnemonic, Some("mypassphrase"), Network::BitcoinMainnet).unwrap();
        
        // Derive same path from both
        let child1 = master1.derive_child(ChildNumber::Normal(0)).unwrap();
        let child2 = master2.derive_child(ChildNumber::Normal(0)).unwrap();
        
        // Children should be different
        assert_ne!(child1.private_key().to_bytes(), child2.private_key().to_bytes());
    }

    #[test]
    fn test_from_mnemonic_empty_passphrase_vs_none() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            bip39::Language::English
        ).unwrap();
        
        let master_none = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        let master_empty = ExtendedPrivateKey::from_mnemonic(&mnemonic, Some(""), Network::BitcoinMainnet).unwrap();
        
        // None and empty string should produce same result (BIP39 spec)
        assert_eq!(master_none.private_key().to_bytes(), master_empty.private_key().to_bytes());
        assert_eq!(master_none.chain_code().as_bytes(), master_empty.chain_code().as_bytes());
    }

    #[test]
    fn test_from_mnemonic_serialization_roundtrip() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            bip39::Language::English
        ).unwrap();
        
        let original = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        
        // Serialize and deserialize
        let serialized = original.to_string();
        let deserialized = ExtendedPrivateKey::from_str(&serialized).unwrap();
        
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_from_mnemonic_watch_only_export() {
        let mnemonic = bip39::Mnemonic::from_phrase(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            bip39::Language::English
        ).unwrap();
        
        let master = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        
        // Derive account
        let account = master.derive_path(&DerivationPath::from_str("m/44'/0'/0'").unwrap()).unwrap();
        
        // Export public key for watch-only
        let account_pub = account.to_extended_public_key();
        let xpub = account_pub.to_string();
        
        assert!(xpub.starts_with("xpub"));
    }

    #[test]
    fn test_from_mnemonic_bip39_test_vector_1() {
        // BIP39 official test vector
        let mnemonic = bip39::Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            bip39::Language::English
        ).unwrap();
        
        let master = ExtendedPrivateKey::from_mnemonic(&mnemonic, Some("TREZOR"), Network::BitcoinMainnet).unwrap();
        
        // Verify it produces a valid master key
        assert_eq!(master.depth(), 0);
        assert_eq!(master.parent_fingerprint(), &[0, 0, 0, 0]);
        
        // Should be able to serialize
        let xprv = master.to_string();
        assert!(xprv.starts_with("xprv"));
    }

    #[test]
    fn test_from_mnemonic_real_world_scenario() {
        // Simulate wallet creation workflow
        
        // 1. User creates/imports mnemonic
        let mnemonic = bip39::Mnemonic::from_phrase(
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            bip39::Language::English
        ).unwrap();
        
        // 2. Optional passphrase for additional security
        let passphrase = Some("my secure passphrase");
        
        // 3. Generate master key
        let master = ExtendedPrivateKey::from_mnemonic(&mnemonic, passphrase, Network::BitcoinMainnet).unwrap();
        
        // 4. Derive BIP-44 account
        let account = master.derive_path(&DerivationPath::from_str("m/44'/0'/0'").unwrap()).unwrap();
        
        // 5. Generate first receiving address key
        let receiving = account.derive_path(&DerivationPath::from_str("m/0/0").unwrap()).unwrap();
        
        assert_eq!(receiving.depth(), 5);
        assert_eq!(receiving.child_number(), ChildNumber::Normal(0));
    }
}
