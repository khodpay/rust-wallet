//! Signed EIP-1559 transaction.
//!
//! This module provides the `SignedTransaction` struct representing a fully
//! signed EIP-1559 transaction ready for broadcast.

use crate::{Eip1559Transaction, Signature};
use primitive_types::U256;
use rlp::RlpStream;
use sha3::{Digest, Keccak256};

/// A signed EIP-1559 transaction ready for broadcast.
///
/// Contains the original transaction and its ECDSA signature.
///
/// # Examples
///
/// ```rust
/// use khodpay_signing::{
///     Bip44Signer, ChainId, Eip1559Transaction, SignedTransaction, Wei,
/// };
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
///     .to(signer.address())
///     .value(Wei::from_ether(1))
///     .build()
///     .unwrap();
///
/// let signature = signer.sign_transaction(&tx).unwrap();
/// let signed_tx = SignedTransaction::new(tx, signature);
///
/// // Get raw transaction for eth_sendRawTransaction
/// let raw = signed_tx.to_raw_transaction();
/// assert!(raw.starts_with("0x02"));
///
/// // Get transaction hash
/// let hash = signed_tx.tx_hash();
/// assert_eq!(hash.len(), 32);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransaction {
    /// The unsigned transaction.
    transaction: Eip1559Transaction,
    /// The ECDSA signature.
    signature: Signature,
}

impl SignedTransaction {
    /// Creates a new signed transaction.
    ///
    /// # Arguments
    ///
    /// * `transaction` - The unsigned transaction
    /// * `signature` - The ECDSA signature
    pub fn new(transaction: Eip1559Transaction, signature: Signature) -> Self {
        Self {
            transaction,
            signature,
        }
    }

    /// Returns a reference to the unsigned transaction.
    pub fn transaction(&self) -> &Eip1559Transaction {
        &self.transaction
    }

    /// Returns a reference to the signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Encodes the signed transaction as RLP bytes.
    ///
    /// Returns `0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
    /// gas_limit, to, value, data, access_list, v, r, s])`.
    pub fn encode(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(12);

        // Transaction fields (9 items)
        stream.append(&u64::from(self.transaction.chain_id));
        stream.append(&self.transaction.nonce);
        append_u256(&mut stream, self.transaction.max_priority_fee_per_gas.as_u256());
        append_u256(&mut stream, self.transaction.max_fee_per_gas.as_u256());
        stream.append(&self.transaction.gas_limit);

        // to (address or empty for contract creation)
        match &self.transaction.to {
            Some(addr) => stream.append(&addr.as_bytes().as_slice()),
            None => stream.append_empty_data(),
        };

        append_u256(&mut stream, self.transaction.value.as_u256());
        stream.append(&self.transaction.data);

        // access_list
        encode_access_list(&mut stream, &self.transaction.access_list);

        // Signature fields (3 items)
        // v is the recovery ID (0 or 1) for EIP-1559
        stream.append(&self.signature.v);
        
        // r and s as big-endian bytes with leading zeros stripped
        append_signature_component(&mut stream, &self.signature.r);
        append_signature_component(&mut stream, &self.signature.s);

        // Prepend type byte (0x02 for EIP-1559)
        let mut encoded = vec![Eip1559Transaction::TYPE];
        encoded.extend_from_slice(&stream.out());
        encoded
    }

    /// Returns the raw transaction as a hex string with 0x prefix.
    ///
    /// This is the format expected by `eth_sendRawTransaction`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::{
    ///     Bip44Signer, ChainId, Eip1559Transaction, SignedTransaction, Wei,
    /// };
    ///
    /// let signer = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();
    /// let tx = Eip1559Transaction::builder()
    ///     .chain_id(ChainId::BscMainnet)
    ///     .nonce(0)
    ///     .max_priority_fee_per_gas(Wei::from_gwei(1))
    ///     .max_fee_per_gas(Wei::from_gwei(5))
    ///     .gas_limit(21000)
    ///     .build()
    ///     .unwrap();
    ///
    /// let signature = signer.sign_transaction(&tx).unwrap();
    /// let signed_tx = SignedTransaction::new(tx, signature);
    ///
    /// let raw = signed_tx.to_raw_transaction();
    /// assert!(raw.starts_with("0x02"));
    /// ```
    pub fn to_raw_transaction(&self) -> String {
        format!("0x{}", hex::encode(self.encode()))
    }

    /// Computes the transaction hash.
    ///
    /// The transaction hash is `keccak256(encoded_signed_tx)`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::{
    ///     Bip44Signer, ChainId, Eip1559Transaction, SignedTransaction, Wei,
    /// };
    ///
    /// let signer = Bip44Signer::from_private_key(&[1u8; 32]).unwrap();
    /// let tx = Eip1559Transaction::builder()
    ///     .chain_id(ChainId::BscMainnet)
    ///     .nonce(0)
    ///     .max_priority_fee_per_gas(Wei::from_gwei(1))
    ///     .max_fee_per_gas(Wei::from_gwei(5))
    ///     .gas_limit(21000)
    ///     .build()
    ///     .unwrap();
    ///
    /// let signature = signer.sign_transaction(&tx).unwrap();
    /// let signed_tx = SignedTransaction::new(tx, signature);
    ///
    /// let hash = signed_tx.tx_hash();
    /// assert_eq!(hash.len(), 32);
    /// ```
    pub fn tx_hash(&self) -> [u8; 32] {
        let encoded = self.encode();
        let hash = Keccak256::digest(&encoded);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Returns the transaction hash as a hex string with 0x prefix.
    pub fn tx_hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.tx_hash()))
    }
}

/// Appends a U256 value to the RLP stream.
fn append_u256(stream: &mut RlpStream, value: U256) {
    if value.is_zero() {
        stream.append_empty_data();
    } else {
        let mut bytes = [0u8; 32];
        value.to_big_endian(&mut bytes);
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
        stream.append(&&bytes[start..]);
    }
}

/// Appends a signature component (r or s) to the RLP stream.
fn append_signature_component(stream: &mut RlpStream, component: &[u8; 32]) {
    // Strip leading zeros
    let start = component.iter().position(|&b| b != 0).unwrap_or(32);
    if start == 32 {
        stream.append_empty_data();
    } else {
        stream.append(&&component[start..]);
    }
}

/// Encodes the access list into the RLP stream.
fn encode_access_list(stream: &mut RlpStream, access_list: &[crate::AccessListItem]) {
    stream.begin_list(access_list.len());
    for item in access_list {
        stream.begin_list(2);
        stream.append(&item.address.as_bytes().as_slice());
        stream.begin_list(item.storage_keys.len());
        for key in &item.storage_keys {
            stream.append(&key.as_slice());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Address, Bip44Signer, ChainId, Wei};

    fn test_signer() -> Bip44Signer {
        Bip44Signer::from_private_key(&[1u8; 32]).unwrap()
    }

    fn test_transaction() -> Eip1559Transaction {
        Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap()
    }

    fn test_signed_transaction() -> SignedTransaction {
        let signer = test_signer();
        let tx = test_transaction();
        let signature = signer.sign_transaction(&tx).unwrap();
        SignedTransaction::new(tx, signature)
    }

    // ==================== Construction Tests ====================

    #[test]
    fn test_new() {
        let tx = test_transaction();
        let signature = Signature::new([1u8; 32], [2u8; 32], 0);
        let signed = SignedTransaction::new(tx.clone(), signature);

        assert_eq!(signed.transaction(), &tx);
        assert_eq!(signed.signature(), &signature);
    }

    #[test]
    fn test_transaction_accessor() {
        let signed = test_signed_transaction();
        assert_eq!(signed.transaction().chain_id, ChainId::BscMainnet);
    }

    #[test]
    fn test_signature_accessor() {
        let signed = test_signed_transaction();
        assert!(signed.signature().v <= 1);
    }

    // ==================== Encoding Tests ====================

    #[test]
    fn test_encode_type_prefix() {
        let signed = test_signed_transaction();
        let encoded = signed.encode();
        assert_eq!(encoded[0], 0x02);
    }

    #[test]
    fn test_encode_not_empty() {
        let signed = test_signed_transaction();
        let encoded = signed.encode();
        assert!(encoded.len() > 1);
    }

    #[test]
    fn test_encode_deterministic() {
        let signed = test_signed_transaction();
        let encoded1 = signed.encode();
        let encoded2 = signed.encode();
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_encode_includes_signature() {
        let tx = test_transaction();
        let signature = Signature::new([0xab; 32], [0xcd; 32], 1);
        let signed = SignedTransaction::new(tx, signature);

        let encoded = signed.encode();
        let hex = hex::encode(&encoded);

        // The signature bytes should appear in the encoding
        assert!(hex.contains("ab"));
        assert!(hex.contains("cd"));
    }

    // ==================== Raw Transaction Tests ====================

    #[test]
    fn test_to_raw_transaction_prefix() {
        let signed = test_signed_transaction();
        let raw = signed.to_raw_transaction();
        assert!(raw.starts_with("0x02"));
    }

    #[test]
    fn test_to_raw_transaction_hex() {
        let signed = test_signed_transaction();
        let raw = signed.to_raw_transaction();

        // Should be valid hex after 0x prefix
        assert!(raw.starts_with("0x"));
        let hex_part = &raw[2..];
        assert!(hex::decode(hex_part).is_ok());
    }

    #[test]
    fn test_to_raw_transaction_deterministic() {
        let signed = test_signed_transaction();
        let raw1 = signed.to_raw_transaction();
        let raw2 = signed.to_raw_transaction();
        assert_eq!(raw1, raw2);
    }

    // ==================== Transaction Hash Tests ====================

    #[test]
    fn test_tx_hash_length() {
        let signed = test_signed_transaction();
        let hash = signed.tx_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let signed = test_signed_transaction();
        let hash1 = signed.tx_hash();
        let hash2 = signed.tx_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_tx_hash_different_for_different_tx() {
        let signer = test_signer();

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

        let signed1 = SignedTransaction::new(tx1, sig1);
        let signed2 = SignedTransaction::new(tx2, sig2);

        assert_ne!(signed1.tx_hash(), signed2.tx_hash());
    }

    #[test]
    fn test_tx_hash_hex() {
        let signed = test_signed_transaction();
        let hash_hex = signed.tx_hash_hex();

        assert!(hash_hex.starts_with("0x"));
        assert_eq!(hash_hex.len(), 66); // 0x + 64 hex chars
    }

    // ==================== With Recipient Tests ====================

    #[test]
    fn test_encode_with_recipient() {
        let signer = test_signer();
        let recipient: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap();

        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .to(recipient)
            .value(Wei::from_ether(1))
            .build()
            .unwrap();

        let signature = signer.sign_transaction(&tx).unwrap();
        let signed = SignedTransaction::new(tx, signature);

        let raw = signed.to_raw_transaction();
        assert!(raw.starts_with("0x02"));
    }

    // ==================== Clone/Eq Tests ====================

    #[test]
    fn test_clone() {
        let signed = test_signed_transaction();
        let cloned = signed.clone();
        assert_eq!(signed, cloned);
    }

    #[test]
    fn test_equality() {
        let tx = test_transaction();
        let sig = Signature::new([1u8; 32], [2u8; 32], 0);

        let signed1 = SignedTransaction::new(tx.clone(), sig);
        let signed2 = SignedTransaction::new(tx, sig);

        assert_eq!(signed1, signed2);
    }

    #[test]
    fn test_inequality_different_signature() {
        let tx = test_transaction();
        let sig1 = Signature::new([1u8; 32], [2u8; 32], 0);
        let sig2 = Signature::new([1u8; 32], [2u8; 32], 1);

        let signed1 = SignedTransaction::new(tx.clone(), sig1);
        let signed2 = SignedTransaction::new(tx, sig2);

        assert_ne!(signed1, signed2);
    }

    // ==================== Debug Tests ====================

    #[test]
    fn test_debug() {
        let signed = test_signed_transaction();
        let debug = format!("{:?}", signed);
        assert!(debug.contains("SignedTransaction"));
    }
}
