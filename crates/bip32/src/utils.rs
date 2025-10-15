//! Utility functions and convenience methods for common BIP32 operations.
//!
//! This module provides ergonomic wrappers around common patterns to reduce
//! boilerplate in application code.

use crate::{ExtendedPrivateKey, ExtendedPublicKey, Network, Result};

/// Generates a master keypair (both private and public) from a seed.
///
/// This is a convenience function that combines [`ExtendedPrivateKey::from_seed()`]
/// and [`ExtendedPrivateKey::to_extended_public_key()`] into a single call.
///
/// # Use Case
///
/// Most wallet applications need both the private key (for signing) and public key
/// (for address generation and watch-only mode). This function returns both in one call.
///
/// # Parameters
///
/// * `seed` - A cryptographic seed (typically 512 bits / 64 bytes from BIP39)
/// * `network` - The cryptocurrency network (Bitcoin mainnet, testnet, etc.)
///
/// # Returns
///
/// A tuple containing:
/// - `ExtendedPrivateKey` - Master private key for signing and private key derivation
/// - `ExtendedPublicKey` - Master public key for address generation and watch-only mode
///
/// Both keys have:
/// - `depth` = 0 (master keys)
/// - `parent_fingerprint` = [0, 0, 0, 0]
/// - `child_number` = 0
/// - Same chain code (required for key derivation)
///
/// # Errors
///
/// Returns an error if:
/// - The seed is too short (minimum 16 bytes recommended)
/// - The derived private key is invalid (extremely rare, < 2^-127 probability)
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust
/// use bip32::{utils::generate_master_keypair, Network};
///
/// let seed = [0x01; 64];
/// let (master_priv, master_pub) = generate_master_keypair(&seed, Network::BitcoinMainnet)?;
///
/// // Both keys are ready to use
/// assert_eq!(master_priv.depth(), 0);
/// assert_eq!(master_pub.depth(), 0);
/// assert_eq!(master_priv.fingerprint(), master_pub.fingerprint());
/// # Ok::<(), bip32::Error>(())
/// ```
///
/// ## Complete Wallet Setup
///
/// ```rust
/// use bip32::{utils::generate_master_keypair, Network, DerivationPath};
/// use bip39::{Mnemonic, WordCount, Language};
/// use std::str::FromStr;
///
/// // 1. Generate mnemonic
/// let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;
/// let seed = mnemonic.to_seed("")?;
///
/// // 2. Generate both keys at once
/// let (master_priv, master_pub) = generate_master_keypair(&seed, Network::BitcoinMainnet)?;
///
/// // 3. Export for backup
/// let xprv = master_priv.to_string();  // Store securely
/// let xpub = master_pub.to_string();   // Can share for watch-only
///
/// assert!(xprv.starts_with("xprv"));
/// assert!(xpub.starts_with("xpub"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## Equivalent to Manual Approach
///
/// ```rust
/// use bip32::{ExtendedPrivateKey, Network, utils::generate_master_keypair};
///
/// let seed = [0x02; 64];
///
/// // Using utility function
/// let (priv1, pub1) = generate_master_keypair(&seed, Network::BitcoinMainnet)?;
///
/// // Equivalent manual approach
/// let priv2 = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
/// let pub2 = priv2.to_extended_public_key();
///
/// // Results are identical
/// assert_eq!(priv1.private_key().to_bytes(), priv2.private_key().to_bytes());
/// assert_eq!(pub1.public_key().to_bytes(), pub2.public_key().to_bytes());
/// # Ok::<(), bip32::Error>(())
/// ```
pub fn generate_master_keypair(
    seed: &[u8],
    network: Network,
) -> Result<(ExtendedPrivateKey, ExtendedPublicKey)> {
    let private_key = ExtendedPrivateKey::from_seed(seed, network)?;
    let public_key = private_key.to_extended_public_key();
    Ok((private_key, public_key))
}

/// Derives a keypair (both private and public) from an extended private key using a derivation path.
///
/// This is a convenience function that combines [`ExtendedPrivateKey::derive_path()`]
/// and [`ExtendedPrivateKey::to_extended_public_key()`] into a single call.
///
/// # Use Case
///
/// Most wallet applications need to derive account keys or address keys and require
/// both the private key (for signing) and public key (for address generation). This
/// function returns both in one call.
///
/// # Parameters
///
/// * `master_key` - The master or parent extended private key
/// * `path` - The BIP-32 derivation path (e.g., "m/44'/0'/0'")
///
/// # Returns
///
/// A tuple containing:
/// - `ExtendedPrivateKey` - Derived private key for signing
/// - `ExtendedPublicKey` - Derived public key for address generation
///
/// Both keys will have:
/// - Appropriate depth based on the path
/// - Matching fingerprints
/// - Same chain code (required for further derivation)
/// - Network inherited from master key
///
/// # Errors
///
/// Returns an error if:
/// - Attempting hardened derivation from a public key (not applicable here)
/// - Invalid key derivation (extremely rare, < 2^-127 probability per step)
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust
/// use bip32::{ExtendedPrivateKey, Network, DerivationPath, utils::derive_keypair_from_path};
/// use std::str::FromStr;
///
/// let seed = [0x01; 64];
/// let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
///
/// // Derive BIP-44 account keys
/// let path = DerivationPath::from_str("m/44'/0'/0'")?;
/// let (account_priv, account_pub) = derive_keypair_from_path(&master, &path)?;
///
/// assert_eq!(account_priv.depth(), 3);
/// assert_eq!(account_pub.depth(), 3);
/// assert_eq!(account_priv.fingerprint(), account_pub.fingerprint());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## Complete BIP-44 Wallet
///
/// ```rust
/// use bip32::{ExtendedPrivateKey, Network, DerivationPath, utils::derive_keypair_from_path};
/// use bip39::{Mnemonic, WordCount, Language};
/// use std::str::FromStr;
///
/// // 1. Generate mnemonic and master key
/// let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;
/// let master = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet)?;
///
/// // 2. Derive account (m/44'/0'/0')
/// let account_path = DerivationPath::from_str("m/44'/0'/0'")?;
/// let (account_priv, account_pub) = derive_keypair_from_path(&master, &account_path)?;
///
/// // 3. Export xpub for watch-only wallet
/// let xpub = account_pub.to_string();
/// assert!(xpub.starts_with("xpub"));
///
/// // 4. Derive first receiving address (relative path from account)
/// let receive_path = DerivationPath::from_str("m/0/0")?;
/// let (addr_priv, addr_pub) = derive_keypair_from_path(&account_priv, &receive_path)?;
/// assert_eq!(addr_priv.depth(), 5);  // m/44'/0'/0'/0/0
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## Equivalent to Manual Approach
///
/// ```rust
/// use bip32::{ExtendedPrivateKey, Network, DerivationPath, utils::derive_keypair_from_path};
/// use std::str::FromStr;
///
/// let seed = [0x02; 64];
/// let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
/// let path = DerivationPath::from_str("m/0'/1")?;
///
/// // Using utility function
/// let (priv1, pub1) = derive_keypair_from_path(&master, &path)?;
///
/// // Equivalent manual approach
/// let priv2 = master.derive_path(&path)?;
/// let pub2 = priv2.to_extended_public_key();
///
/// // Results are identical
/// assert_eq!(priv1.private_key().to_bytes(), priv2.private_key().to_bytes());
/// assert_eq!(pub1.public_key().to_bytes(), pub2.public_key().to_bytes());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn derive_keypair_from_path(
    master_key: &ExtendedPrivateKey,
    path: &crate::DerivationPath,
) -> Result<(ExtendedPrivateKey, ExtendedPublicKey)> {
    let private_key = master_key.derive_path(path)?;
    let public_key = private_key.to_extended_public_key();
    Ok((private_key, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChildNumber;

    #[test]
    fn test_generate_master_keypair_basic() {
        let seed = [0x01; 64];
        let result = generate_master_keypair(&seed, Network::BitcoinMainnet);

        assert!(result.is_ok());
        let (priv_key, pub_key) = result.unwrap();

        // Both should be master keys
        assert_eq!(priv_key.depth(), 0);
        assert_eq!(pub_key.depth(), 0);
        assert_eq!(priv_key.parent_fingerprint(), &[0, 0, 0, 0]);
        assert_eq!(pub_key.parent_fingerprint(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_generate_master_keypair_fingerprints_match() {
        let seed = [0x02; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Private and public keys should have the same fingerprint
        assert_eq!(priv_key.fingerprint(), pub_key.fingerprint());
    }

    #[test]
    fn test_generate_master_keypair_chain_codes_match() {
        let seed = [0x03; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Chain codes MUST be identical for derivation to work
        assert_eq!(
            priv_key.chain_code().as_bytes(),
            pub_key.chain_code().as_bytes()
        );
    }

    #[test]
    fn test_generate_master_keypair_public_key_derives_from_private() {
        let seed = [0x04; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Public key should match private key's public key
        assert_eq!(
            pub_key.public_key().to_bytes(),
            priv_key.private_key().public_key().serialize()
        );
    }

    #[test]
    fn test_generate_master_keypair_mainnet() {
        let seed = [0x05; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        assert_eq!(priv_key.network(), Network::BitcoinMainnet);
        assert_eq!(pub_key.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_generate_master_keypair_testnet() {
        let seed = [0x06; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinTestnet).unwrap();

        assert_eq!(priv_key.network(), Network::BitcoinTestnet);
        assert_eq!(pub_key.network(), Network::BitcoinTestnet);
    }

    #[test]
    fn test_generate_master_keypair_deterministic() {
        let seed = [0x07; 64];

        let (priv1, pub1) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();
        let (priv2, pub2) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Same seed should produce same keys
        assert_eq!(
            priv1.private_key().to_bytes(),
            priv2.private_key().to_bytes()
        );
        assert_eq!(pub1.public_key().to_bytes(), pub2.public_key().to_bytes());
    }

    #[test]
    fn test_generate_master_keypair_different_seeds() {
        let seed1 = [0x08; 64];
        let seed2 = [0x09; 64];

        let (priv1, pub1) = generate_master_keypair(&seed1, Network::BitcoinMainnet).unwrap();
        let (priv2, pub2) = generate_master_keypair(&seed2, Network::BitcoinMainnet).unwrap();

        // Different seeds should produce different keys
        assert_ne!(
            priv1.private_key().to_bytes(),
            priv2.private_key().to_bytes()
        );
        assert_ne!(pub1.public_key().to_bytes(), pub2.public_key().to_bytes());
    }

    #[test]
    fn test_generate_master_keypair_equivalent_to_manual() {
        let seed = [0x0A; 64];

        // Using utility function
        let (util_priv, util_pub) =
            generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Manual approach
        let manual_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let manual_pub = manual_priv.to_extended_public_key();

        // Should be identical
        assert_eq!(
            util_priv.private_key().to_bytes(),
            manual_priv.private_key().to_bytes()
        );
        assert_eq!(
            util_pub.public_key().to_bytes(),
            manual_pub.public_key().to_bytes()
        );
        assert_eq!(
            util_priv.chain_code().as_bytes(),
            manual_priv.chain_code().as_bytes()
        );
        assert_eq!(
            util_pub.chain_code().as_bytes(),
            manual_pub.chain_code().as_bytes()
        );
    }

    #[test]
    fn test_generate_master_keypair_child_derivation_works() {
        let seed = [0x0B; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Should be able to derive children from both keys
        let priv_child = priv_key.derive_child(ChildNumber::Normal(0)).unwrap();
        let pub_child = pub_key.derive_child(ChildNumber::Normal(0)).unwrap();

        // Children should have matching public keys
        assert_eq!(
            priv_child.private_key().public_key().serialize(),
            pub_child.public_key().to_bytes()
        );
    }

    #[test]
    fn test_generate_master_keypair_serialization() {
        let seed = [0x0C; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Should be able to serialize both keys
        let xprv = priv_key.to_string();
        let xpub = pub_key.to_string();

        assert!(xprv.starts_with("xprv"));
        assert!(xpub.starts_with("xpub"));
    }

    #[test]
    fn test_generate_master_keypair_bip32_test_vector() {
        // BIP-32 Test Vector 1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Should produce valid master keys
        assert_eq!(priv_key.depth(), 0);
        assert_eq!(pub_key.depth(), 0);
        assert_eq!(priv_key.child_number(), ChildNumber::Normal(0));
        assert_eq!(pub_key.child_number(), ChildNumber::Normal(0));
    }

    #[test]
    fn test_generate_master_keypair_with_mnemonic() {
        use bip39::{Language, Mnemonic};

        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English
        ).unwrap();

        let seed = mnemonic.to_seed("").unwrap();
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Should work with BIP39-derived seeds
        assert_eq!(priv_key.depth(), 0);
        assert_eq!(pub_key.depth(), 0);
        assert_eq!(priv_key.fingerprint(), pub_key.fingerprint());
    }

    #[test]
    fn test_generate_master_keypair_min_seed_length() {
        let seed = [0x01; 16]; // Minimum recommended seed length
        let result = generate_master_keypair(&seed, Network::BitcoinMainnet);

        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_master_keypair_standard_seed_length() {
        let seed = [0x02; 64]; // Standard BIP39 seed length
        let result = generate_master_keypair(&seed, Network::BitcoinMainnet);

        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_keypair_from_path_basic() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x10; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/0").unwrap();

        let result = derive_keypair_from_path(&master, &path);
        assert!(result.is_ok());

        let (priv_key, pub_key) = result.unwrap();
        assert_eq!(priv_key.depth(), 1);
        assert_eq!(pub_key.depth(), 1);
    }

    #[test]
    fn test_derive_keypair_from_path_fingerprints_match() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x11; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/0'/1").unwrap();

        let (priv_key, pub_key) = derive_keypair_from_path(&master, &path).unwrap();

        assert_eq!(priv_key.fingerprint(), pub_key.fingerprint());
    }

    #[test]
    fn test_derive_keypair_from_path_chain_codes_match() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x12; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/44'/0'/0'").unwrap();

        let (priv_key, pub_key) = derive_keypair_from_path(&master, &path).unwrap();

        assert_eq!(
            priv_key.chain_code().as_bytes(),
            pub_key.chain_code().as_bytes()
        );
    }

    #[test]
    fn test_derive_keypair_from_path_bip44_account() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x13; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // BIP-44 account path: m/44'/0'/0'
        let path = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        let (account_priv, account_pub) = derive_keypair_from_path(&master, &path).unwrap();

        assert_eq!(account_priv.depth(), 3);
        assert_eq!(account_pub.depth(), 3);
        assert_eq!(account_priv.network(), Network::BitcoinMainnet);
        assert_eq!(account_pub.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_derive_keypair_from_path_bip44_address() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x14; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Full BIP-44 path: m/44'/0'/0'/0/0
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let (addr_priv, addr_pub) = derive_keypair_from_path(&master, &path).unwrap();

        assert_eq!(addr_priv.depth(), 5);
        assert_eq!(addr_pub.depth(), 5);
    }

    #[test]
    fn test_derive_keypair_from_path_hardened() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x15; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/0'/1'/2'").unwrap();

        let result = derive_keypair_from_path(&master, &path);
        assert!(result.is_ok());

        let (priv_key, pub_key) = result.unwrap();
        assert_eq!(priv_key.depth(), 3);
        assert_eq!(pub_key.depth(), 3);
    }

    #[test]
    fn test_derive_keypair_from_path_normal() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x16; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/0/1/2").unwrap();

        let result = derive_keypair_from_path(&master, &path);
        assert!(result.is_ok());

        let (priv_key, pub_key) = result.unwrap();
        assert_eq!(priv_key.depth(), 3);
        assert_eq!(pub_key.depth(), 3);
    }

    #[test]
    fn test_derive_keypair_from_path_mixed() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x17; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Mix of hardened and normal
        let path = DerivationPath::from_str("m/44'/0'/0'/0/5").unwrap();
        let (priv_key, pub_key) = derive_keypair_from_path(&master, &path).unwrap();

        assert_eq!(priv_key.depth(), 5);
        assert_eq!(pub_key.depth(), 5);
        assert_eq!(priv_key.child_number(), ChildNumber::Normal(5));
    }

    #[test]
    fn test_derive_keypair_from_path_equivalent_to_manual() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x18; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/0'/1/2'").unwrap();

        // Using utility function
        let (util_priv, util_pub) = derive_keypair_from_path(&master, &path).unwrap();

        // Manual approach
        let manual_priv = master.derive_path(&path).unwrap();
        let manual_pub = manual_priv.to_extended_public_key();

        // Should be identical
        assert_eq!(
            util_priv.private_key().to_bytes(),
            manual_priv.private_key().to_bytes()
        );
        assert_eq!(
            util_pub.public_key().to_bytes(),
            manual_pub.public_key().to_bytes()
        );
    }

    #[test]
    fn test_derive_keypair_from_path_deterministic() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x19; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/44'/0'/0'").unwrap();

        let (priv1, pub1) = derive_keypair_from_path(&master, &path).unwrap();
        let (priv2, pub2) = derive_keypair_from_path(&master, &path).unwrap();

        // Same path should produce same keys
        assert_eq!(
            priv1.private_key().to_bytes(),
            priv2.private_key().to_bytes()
        );
        assert_eq!(pub1.public_key().to_bytes(), pub2.public_key().to_bytes());
    }

    #[test]
    fn test_derive_keypair_from_path_network_inherited() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x1A; 64];

        // Mainnet
        let mainnet_master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/0").unwrap();
        let (mainnet_priv, mainnet_pub) = derive_keypair_from_path(&mainnet_master, &path).unwrap();

        assert_eq!(mainnet_priv.network(), Network::BitcoinMainnet);
        assert_eq!(mainnet_pub.network(), Network::BitcoinMainnet);

        // Testnet
        let testnet_master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
        let (testnet_priv, testnet_pub) = derive_keypair_from_path(&testnet_master, &path).unwrap();

        assert_eq!(testnet_priv.network(), Network::BitcoinTestnet);
        assert_eq!(testnet_pub.network(), Network::BitcoinTestnet);
    }

    #[test]
    fn test_derive_keypair_from_path_further_derivation() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x1B; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Derive account
        let account_path = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        let (account_priv, _) = derive_keypair_from_path(&master, &account_path).unwrap();

        // Further derive from account
        let receive_path = DerivationPath::from_str("m/0/0").unwrap();
        let (addr_priv, addr_pub) = derive_keypair_from_path(&account_priv, &receive_path).unwrap();

        assert_eq!(addr_priv.depth(), 5);
        assert_eq!(addr_pub.depth(), 5);
    }

    #[test]
    fn test_derive_keypair_from_path_serialization() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x1C; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/44'/0'/0'").unwrap();

        let (priv_key, pub_key) = derive_keypair_from_path(&master, &path).unwrap();

        // Should be able to serialize
        let xprv = priv_key.to_string();
        let xpub = pub_key.to_string();

        assert!(xprv.starts_with("xprv"));
        assert!(xpub.starts_with("xpub"));
    }

    #[test]
    fn test_derive_keypair_from_path_with_mnemonic() {
        use crate::DerivationPath;
        use bip39::{Language, Mnemonic};
        use std::str::FromStr;

        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English
        ).unwrap();

        let master =
            ExtendedPrivateKey::from_mnemonic(&mnemonic, None, Network::BitcoinMainnet).unwrap();
        let path = DerivationPath::from_str("m/44'/0'/0'").unwrap();

        let (priv_key, pub_key) = derive_keypair_from_path(&master, &path).unwrap();

        assert_eq!(priv_key.depth(), 3);
        assert_eq!(pub_key.depth(), 3);
        assert_eq!(priv_key.fingerprint(), pub_key.fingerprint());
    }

    #[test]
    fn test_derive_keypair_from_path_watch_only_workflow() {
        use crate::DerivationPath;
        use std::str::FromStr;

        let seed = [0x1D; 64];
        let master = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Derive account
        let account_path = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        let (_account_priv, account_pub) =
            derive_keypair_from_path(&master, &account_path).unwrap();

        // Export xpub for watch-only wallet
        let xpub = account_pub.to_string();
        assert!(xpub.starts_with("xpub"));

        // Verify can derive addresses from public key
        let receive_child = account_pub.derive_child(ChildNumber::Normal(0)).unwrap();
        assert_eq!(receive_child.depth(), 4);
    }
}
