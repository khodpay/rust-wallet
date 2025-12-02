//! Transaction signer using BIP-44 derived keys.
//!
//! This module provides the `Bip44Signer` which wraps a `khodpay_bip44::Account`
//! and provides transaction signing capabilities.
//!
//! # Security
//!
//! The `Bip44Signer` holds a private signing key in memory. The key is automatically
//! zeroized when the signer is dropped, preventing sensitive data from lingering
//! in memory. The underlying `k256::SigningKey` implements `Zeroize`.

use crate::{Address, Eip1559Transaction, Error, Result, Signature};
use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

/// A transaction signer using BIP-44 derived keys.
///
/// `Bip44Signer` wraps a `khodpay_bip44::Account` and provides methods for
/// signing EIP-1559 transactions and deriving the associated EVM address.
///
/// # Examples
///
/// ```rust,ignore
/// use khodpay_signing::Bip44Signer;
/// use khodpay_bip44::{Wallet, Purpose, CoinType, Language};
/// use khodpay_bip32::Network;
///
/// let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// let mut wallet = Wallet::from_mnemonic(mnemonic, "", Language::English, Network::BitcoinMainnet)?;
/// let account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0)?;
///
/// let signer = Bip44Signer::new(account, 0)?;
/// let address = signer.address();
/// ```
pub struct Bip44Signer {
    /// The signing key derived from the BIP-44 account.
    signing_key: SigningKey,
    /// The EVM address derived from the public key.
    address: Address,
}

impl Bip44Signer {
    /// Creates a new signer from a BIP-44 account and address index.
    ///
    /// # Arguments
    ///
    /// * `account` - The BIP-44 account to derive keys from
    /// * `address_index` - The address index within the account (external chain)
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn new(account: &khodpay_bip44::Account, address_index: u32) -> Result<Self> {
        // Derive the external address at the given index
        let extended_key = account.derive_external(address_index)?;

        // Get the private key bytes from the extended key, wrapped in Zeroizing
        // to ensure the bytes are zeroed when dropped
        let private_key_bytes: Zeroizing<[u8; 32]> =
            Zeroizing::new(extended_key.private_key().to_bytes());

        // Create the signing key (k256::SigningKey implements Zeroize internally)
        let signing_key = SigningKey::from_bytes(private_key_bytes.as_ref().into())
            .map_err(|e| Error::SigningError(format!("Invalid private key: {}", e)))?;

        // Derive the address from the public key
        let verifying_key = signing_key.verifying_key();
        let address = Self::address_from_verifying_key(verifying_key)?;

        Ok(Self {
            signing_key,
            address,
        })
    }

    /// Creates a signer directly from a 32-byte private key.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The 32-byte private key
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Bip44Signer;
    ///
    /// let private_key = [1u8; 32]; // Example key (don't use in production!)
    /// let signer = Bip44Signer::from_private_key(&private_key).unwrap();
    /// ```
    pub fn from_private_key(private_key: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(private_key.into())
            .map_err(|e| Error::SigningError(format!("Invalid private key: {}", e)))?;

        let verifying_key = signing_key.verifying_key();
        let address = Self::address_from_verifying_key(verifying_key)?;

        Ok(Self {
            signing_key,
            address,
        })
    }

    /// Returns the EVM address associated with this signer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::Bip44Signer;
    ///
    /// let private_key = [1u8; 32];
    /// let signer = Bip44Signer::from_private_key(&private_key).unwrap();
    /// let address = signer.address();
    /// println!("Address: {}", address);
    /// ```
    pub fn address(&self) -> Address {
        self.address
    }

    /// Signs a message hash and returns the signature.
    ///
    /// # Arguments
    ///
    /// * `hash` - The 32-byte message hash to sign
    ///
    /// # Returns
    ///
    /// The ECDSA signature with recovery ID.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<Signature> {
        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(hash)
            .map_err(|e| Error::SigningError(format!("Signing failed: {}", e)))?;

        let r_bytes: [u8; 32] = signature.r().to_bytes().into();
        let s_bytes: [u8; 32] = signature.s().to_bytes().into();
        let v = recovery_id.to_byte();

        Ok(Signature::new(r_bytes, s_bytes, v))
    }

    /// Signs an EIP-1559 transaction.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to sign
    ///
    /// # Returns
    ///
    /// The ECDSA signature for the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::{Bip44Signer, Eip1559Transaction, ChainId, Wei};
    ///
    /// let private_key = [1u8; 32];
    /// let signer = Bip44Signer::from_private_key(&private_key).unwrap();
    ///
    /// let tx = Eip1559Transaction::builder()
    ///     .chain_id(ChainId::BscMainnet)
    ///     .nonce(0)
    ///     .max_priority_fee_per_gas(Wei::from_gwei(1))
    ///     .max_fee_per_gas(Wei::from_gwei(5))
    ///     .gas_limit(21000)
    ///     .value(Wei::ZERO)
    ///     .build()
    ///     .unwrap();
    ///
    /// let signature = signer.sign_transaction(&tx).unwrap();
    /// ```
    pub fn sign_transaction(&self, tx: &Eip1559Transaction) -> Result<Signature> {
        let hash = tx.signing_hash();
        self.sign_hash(&hash)
    }

    /// Derives an EVM address from a verifying (public) key.
    fn address_from_verifying_key(verifying_key: &VerifyingKey) -> Result<Address> {
        // Get uncompressed public key (65 bytes with 0x04 prefix)
        let pubkey_uncompressed = verifying_key.to_encoded_point(false);
        let pubkey_bytes = pubkey_uncompressed.as_bytes();

        // Skip the 0x04 prefix, take the 64-byte public key
        if pubkey_bytes.len() != 65 || pubkey_bytes[0] != 0x04 {
            return Err(Error::SigningError("Invalid public key format".to_string()));
        }

        Address::from_public_key_bytes(&pubkey_bytes[1..])
    }
}

/// Recovers the signer's address from a signature and message hash.
///
/// # Arguments
///
/// * `hash` - The 32-byte message hash that was signed
/// * `signature` - The signature to recover from
///
/// # Returns
///
/// The EVM address of the signer.
///
/// # Errors
///
/// Returns an error if recovery fails.
pub fn recover_signer(hash: &[u8; 32], signature: &Signature) -> Result<Address> {
    let recovery_id = RecoveryId::from_byte(signature.v)
        .ok_or_else(|| Error::SigningError("Invalid recovery ID".to_string()))?;

    let r: &k256::FieldBytes = (&signature.r).into();
    let s: &k256::FieldBytes = (&signature.s).into();

    let ecdsa_sig = k256::ecdsa::Signature::from_scalars(*r, *s)
        .map_err(|e| Error::SigningError(format!("Invalid signature: {}", e)))?;

    let verifying_key = VerifyingKey::recover_from_prehash(hash, &ecdsa_sig, recovery_id)
        .map_err(|e| Error::SigningError(format!("Recovery failed: {}", e)))?;

    Bip44Signer::address_from_verifying_key(&verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChainId, Wei};

    // Known test vector: private key 1
    const TEST_PRIVATE_KEY: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

    // Expected address for private key 1
    const EXPECTED_ADDRESS: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

    // ==================== Construction Tests ====================

    #[test]
    fn test_from_private_key() {
        let signer = Bip44Signer::from_private_key(&TEST_PRIVATE_KEY).unwrap();
        assert_eq!(signer.address().to_checksum_string(), EXPECTED_ADDRESS);
    }

    #[test]
    fn test_from_private_key_invalid() {
        // All zeros is not a valid private key
        let invalid_key = [0u8; 32];
        assert!(Bip44Signer::from_private_key(&invalid_key).is_err());
    }

    // ==================== Address Tests ====================

    #[test]
    fn test_address() {
        let signer = Bip44Signer::from_private_key(&TEST_PRIVATE_KEY).unwrap();
        let address = signer.address();

        assert_eq!(address.to_checksum_string(), EXPECTED_ADDRESS);
    }

    #[test]
    fn test_address_deterministic() {
        let signer1 = Bip44Signer::from_private_key(&TEST_PRIVATE_KEY).unwrap();
        let signer2 = Bip44Signer::from_private_key(&TEST_PRIVATE_KEY).unwrap();

        assert_eq!(signer1.address(), signer2.address());
    }

    // ==================== Signing Tests ====================

    #[test]
    fn test_sign_hash() {
        let signer = Bip44Signer::from_private_key(&TEST_PRIVATE_KEY).unwrap();
        let hash = [0u8; 32];

        let signature = signer.sign_hash(&hash).unwrap();

        // Signature should have valid components
        assert!(signature.v <= 1);
        // r and s should not be all zeros (extremely unlikely for valid signature)
        assert_ne!(signature.r, [0u8; 32]);
        assert_ne!(signature.s, [0u8; 32]);
    }

    #[test]
    fn test_sign_hash_deterministic() {
        let signer = Bip44Signer::from_private_key(&TEST_PRIVATE_KEY).unwrap();
        let hash = [1u8; 32];

        let sig1 = signer.sign_hash(&hash).unwrap();
        let sig2 = signer.sign_hash(&hash).unwrap();

        // RFC 6979 deterministic signatures
        assert_eq!(sig1.r, sig2.r);
        assert_eq!(sig1.s, sig2.s);
    }

    #[test]
    fn test_sign_transaction() {
        let signer = Bip44Signer::from_private_key(&TEST_PRIVATE_KEY).unwrap();

        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .value(Wei::ZERO)
            .build()
            .unwrap();

        let signature = signer.sign_transaction(&tx).unwrap();

        assert!(signature.v <= 1);
    }

    #[test]
    fn test_sign_different_transactions() {
        let signer = Bip44Signer::from_private_key(&TEST_PRIVATE_KEY).unwrap();

        let tx1 = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let tx2 = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(1) // Different nonce
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let sig1 = signer.sign_transaction(&tx1).unwrap();
        let sig2 = signer.sign_transaction(&tx2).unwrap();

        // Different transactions should produce different signatures
        assert_ne!(sig1.r, sig2.r);
    }

    // ==================== Recovery Tests ====================

    #[test]
    fn test_recover_signer() {
        let signer = Bip44Signer::from_private_key(&TEST_PRIVATE_KEY).unwrap();
        let hash = [5u8; 32];

        let signature = signer.sign_hash(&hash).unwrap();
        let recovered = recover_signer(&hash, &signature).unwrap();

        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn test_recover_from_transaction() {
        let signer = Bip44Signer::from_private_key(&TEST_PRIVATE_KEY).unwrap();

        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .value(Wei::from_ether(1))
            .build()
            .unwrap();

        let signature = signer.sign_transaction(&tx).unwrap();
        let hash = tx.signing_hash();
        let recovered = recover_signer(&hash, &signature).unwrap();

        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn test_recover_invalid_recovery_id() {
        let signature = Signature::new([1u8; 32], [2u8; 32], 5); // Invalid v
        let hash = [0u8; 32];

        assert!(recover_signer(&hash, &signature).is_err());
    }

    // ==================== Different Keys Tests ====================

    #[test]
    fn test_different_keys_different_addresses() {
        let key1 = [1u8; 32];
        let mut key2 = [1u8; 32];
        key2[31] = 2;

        let signer1 = Bip44Signer::from_private_key(&key1).unwrap();
        let signer2 = Bip44Signer::from_private_key(&key2).unwrap();

        assert_ne!(signer1.address(), signer2.address());
    }

    #[test]
    fn test_different_keys_different_signatures() {
        let key1 = [1u8; 32];
        let mut key2 = [1u8; 32];
        key2[31] = 2;

        let signer1 = Bip44Signer::from_private_key(&key1).unwrap();
        let signer2 = Bip44Signer::from_private_key(&key2).unwrap();

        let hash = [0u8; 32];
        let sig1 = signer1.sign_hash(&hash).unwrap();
        let sig2 = signer2.sign_hash(&hash).unwrap();

        assert_ne!(sig1.r, sig2.r);
    }
}
