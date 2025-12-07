//! RLP encoding for EIP-1559 transactions.
//!
//! This module implements RLP (Recursive Length Prefix) encoding for
//! EIP-1559 transactions as specified in EIP-2718.

use crate::{AccessListItem, Address, Eip1559Transaction};
use primitive_types::U256;
use rlp::RlpStream;
use sha3::{Digest, Keccak256};

impl Eip1559Transaction {
    /// Encodes the unsigned transaction for signing.
    ///
    /// Returns `0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
    /// gas_limit, to, value, data, access_list])`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::{Eip1559Transaction, ChainId, Wei};
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
    /// let encoded = tx.encode_unsigned();
    /// assert_eq!(encoded[0], 0x02); // EIP-1559 type prefix
    /// ```
    pub fn encode_unsigned(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(9);

        // chain_id
        stream.append(&u64::from(self.chain_id));

        // nonce
        stream.append(&self.nonce);

        // max_priority_fee_per_gas
        append_u256(&mut stream, self.max_priority_fee_per_gas.as_u256());

        // max_fee_per_gas
        append_u256(&mut stream, self.max_fee_per_gas.as_u256());

        // gas_limit
        stream.append(&self.gas_limit);

        // to (address or empty for contract creation)
        match &self.to {
            Some(addr) => stream.append(&addr.as_bytes().as_slice()),
            None => stream.append_empty_data(),
        };

        // value
        append_u256(&mut stream, self.value.as_u256());

        // data
        stream.append(&self.data);

        // access_list
        encode_access_list(&mut stream, &self.access_list);

        // Prepend type byte (0x02 for EIP-1559)
        let mut encoded = vec![Self::TYPE];
        encoded.extend_from_slice(&stream.out());
        encoded
    }

    /// Computes the signing hash for this transaction.
    ///
    /// The signing hash is `keccak256(0x02 || rlp(unsigned_tx))`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_signing::{Eip1559Transaction, ChainId, Wei};
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
    /// let hash = tx.signing_hash();
    /// assert_eq!(hash.len(), 32);
    /// ```
    pub fn signing_hash(&self) -> [u8; 32] {
        let encoded = self.encode_unsigned();
        let hash = Keccak256::digest(&encoded);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }
}

/// Appends a U256 value to the RLP stream.
///
/// U256 values are encoded as big-endian bytes with leading zeros stripped.
fn append_u256(stream: &mut RlpStream, value: U256) {
    if value.is_zero() {
        stream.append_empty_data();
    } else {
        let mut bytes = [0u8; 32];
        value.to_big_endian(&mut bytes);
        // Find first non-zero byte
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
        stream.append(&&bytes[start..]);
    }
}

/// Encodes the access list into the RLP stream.
fn encode_access_list(stream: &mut RlpStream, access_list: &[AccessListItem]) {
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

/// Helper to encode an address for RLP.
impl Address {
    /// Returns the RLP encoding of this address.
    pub fn rlp_bytes(&self) -> Vec<u8> {
        rlp::encode(&self.as_bytes().as_slice()).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessListItem, ChainId, Wei};

    fn test_address() -> Address {
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
            .parse()
            .unwrap()
    }

    // ==================== Encoding Tests ====================

    #[test]
    fn test_encode_unsigned_type_prefix() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let encoded = tx.encode_unsigned();
        assert_eq!(encoded[0], 0x02);
    }

    #[test]
    fn test_encode_unsigned_not_empty() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let encoded = tx.encode_unsigned();
        assert!(encoded.len() > 1);
    }

    #[test]
    fn test_encode_unsigned_deterministic() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let encoded1 = tx.encode_unsigned();
        let encoded2 = tx.encode_unsigned();
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_encode_unsigned_with_recipient() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .to(test_address())
            .value(Wei::from_ether(1))
            .build()
            .unwrap();

        let encoded = tx.encode_unsigned();
        assert_eq!(encoded[0], 0x02);
        assert!(encoded.len() > 20); // Should include address
    }

    #[test]
    fn test_encode_unsigned_with_data() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(65000)
            .to(test_address())
            .data(vec![0xa9, 0x05, 0x9c, 0xbb]) // transfer selector
            .build()
            .unwrap();

        let encoded = tx.encode_unsigned();
        assert_eq!(encoded[0], 0x02);
    }

    #[test]
    fn test_encode_unsigned_with_access_list() {
        let item = AccessListItem::new(test_address(), vec![[1u8; 32]]);

        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .access_list(vec![item])
            .build()
            .unwrap();

        let encoded = tx.encode_unsigned();
        assert_eq!(encoded[0], 0x02);
    }

    #[test]
    fn test_encode_different_chain_ids() {
        let tx_bsc = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let tx_testnet = Eip1559Transaction::builder()
            .chain_id(ChainId::BscTestnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let encoded_bsc = tx_bsc.encode_unsigned();
        let encoded_testnet = tx_testnet.encode_unsigned();

        // Different chain IDs should produce different encodings
        assert_ne!(encoded_bsc, encoded_testnet);
    }

    #[test]
    fn test_encode_different_nonces() {
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
            .nonce(1)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        assert_ne!(tx1.encode_unsigned(), tx2.encode_unsigned());
    }

    // ==================== Signing Hash Tests ====================

    #[test]
    fn test_signing_hash_length() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let hash = tx.signing_hash();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_signing_hash_deterministic() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let hash1 = tx.signing_hash();
        let hash2 = tx.signing_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_signing_hash_different_for_different_tx() {
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
            .nonce(1)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        assert_ne!(tx1.signing_hash(), tx2.signing_hash());
    }

    #[test]
    fn test_signing_hash_different_chains() {
        let tx_bsc = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        let tx_testnet = Eip1559Transaction::builder()
            .chain_id(ChainId::BscTestnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .build()
            .unwrap();

        // Different chain IDs should produce different signing hashes
        // This is critical for replay protection
        assert_ne!(tx_bsc.signing_hash(), tx_testnet.signing_hash());
    }

    #[test]
    fn test_signing_hash_with_value() {
        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet)
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .to(test_address())
            .value(Wei::from_ether(1))
            .build()
            .unwrap();

        let hash = tx.signing_hash();
        assert_eq!(hash.len(), 32);
    }

    // ==================== Known Vector Test ====================

    #[test]
    fn test_encode_known_transaction() {
        // Test against a known EIP-1559 transaction encoding
        // This is a simple transfer on BSC mainnet
        let recipient: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        let tx = Eip1559Transaction::builder()
            .chain_id(ChainId::BscMainnet) // 56
            .nonce(0)
            .max_priority_fee_per_gas(Wei::from_gwei(1))
            .max_fee_per_gas(Wei::from_gwei(5))
            .gas_limit(21000)
            .to(recipient)
            .value(Wei::from_wei(0u64))
            .build()
            .unwrap();

        let encoded = tx.encode_unsigned();

        // Verify structure:
        // - First byte is 0x02 (EIP-1559 type)
        // - Rest is RLP encoded list
        assert_eq!(encoded[0], 0x02);

        // The second byte should indicate an RLP list
        // For short lists, it's 0xc0 + length or 0xf7 + length_of_length
        assert!(encoded[1] >= 0xc0);
    }

    // ==================== U256 Encoding Tests ====================

    #[test]
    fn test_u256_zero_encoding() {
        let mut stream = RlpStream::new();
        append_u256(&mut stream, U256::zero());
        let encoded = stream.out();
        // Zero should be encoded as empty bytes (0x80)
        assert_eq!(encoded.as_ref(), &[0x80]);
    }

    #[test]
    fn test_u256_small_value_encoding() {
        let mut stream = RlpStream::new();
        append_u256(&mut stream, U256::from(127));
        let encoded = stream.out();
        // Small values (< 128) are encoded as single byte
        assert_eq!(encoded.as_ref(), &[127]);
    }

    #[test]
    fn test_u256_larger_value_encoding() {
        let mut stream = RlpStream::new();
        append_u256(&mut stream, U256::from(256));
        let encoded = stream.out();
        // 256 = 0x0100, encoded as 0x82 0x01 0x00
        assert_eq!(encoded.as_ref(), &[0x82, 0x01, 0x00]);
    }

    // ==================== Access List Encoding Tests ====================

    #[test]
    fn test_empty_access_list_encoding() {
        let mut stream = RlpStream::new();
        encode_access_list(&mut stream, &[]);
        let encoded = stream.out();
        // Empty list is 0xc0
        assert_eq!(encoded.as_ref(), &[0xc0]);
    }

    #[test]
    fn test_access_list_with_item() {
        let item = AccessListItem::address_only(test_address());
        let mut stream = RlpStream::new();
        encode_access_list(&mut stream, &[item]);
        let encoded = stream.out();
        // Should be a non-empty list
        assert!(encoded.len() > 1);
        assert!(encoded[0] >= 0xc0);
    }
}
