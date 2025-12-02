//! Integration tests for the khodpay-signing crate.
//!
//! These tests verify the full workflow from mnemonic to signed transaction.

use khodpay_bip32::Network;
use khodpay_bip44::{CoinType, Purpose, Wallet};
use khodpay_signing::{
    Address, Bip44Signer, ChainId, Eip1559Transaction, SignedTransaction, Wei,
    recover_signer, TRANSFER_GAS,
};

/// Standard test mnemonic (DO NOT USE IN PRODUCTION).
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// ==================== Full Workflow Tests ====================

#[test]
fn test_full_workflow_mnemonic_to_signed_transaction() {
    // Step 1: Create wallet from mnemonic
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();

    // Step 2: Get Ethereum account (CoinType 60 for EVM chains)
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();

    // Step 3: Create signer from account
    let signer = Bip44Signer::new(&account, 0).unwrap();
    let sender_address = signer.address();

    // Step 4: Create transaction
    let recipient: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        .parse()
        .unwrap();

    let tx = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .to(recipient)
        .value(Wei::from_ether(1))
        .build()
        .unwrap();

    // Step 5: Sign transaction
    let signature = signer.sign_transaction(&tx).unwrap();

    // Step 6: Create signed transaction
    let signed_tx = SignedTransaction::new(tx.clone(), signature);

    // Step 7: Get raw transaction for broadcast
    let raw_tx = signed_tx.to_raw_transaction();
    assert!(raw_tx.starts_with("0x02"));

    // Step 8: Get transaction hash
    let tx_hash = signed_tx.tx_hash_hex();
    assert!(tx_hash.starts_with("0x"));
    assert_eq!(tx_hash.len(), 66);

    // Step 9: Verify signature recovery
    let recovered = recover_signer(&tx.signing_hash(), &signature).unwrap();
    assert_eq!(recovered, sender_address);
}

#[test]
fn test_workflow_bsc_testnet() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();
    let signer = Bip44Signer::new(&account, 0).unwrap();

    let tx = Eip1559Transaction::builder()
        .chain_id(ChainId::BscTestnet) // Testnet
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .value(Wei::ZERO)
        .build()
        .unwrap();

    let signature = signer.sign_transaction(&tx).unwrap();
    let signed_tx = SignedTransaction::new(tx, signature);

    let raw_tx = signed_tx.to_raw_transaction();
    assert!(raw_tx.starts_with("0x02"));
}

#[test]
fn test_workflow_multiple_addresses() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();

    // Derive multiple addresses
    let signer0 = Bip44Signer::new(&account, 0).unwrap();
    let signer1 = Bip44Signer::new(&account, 1).unwrap();
    let signer2 = Bip44Signer::new(&account, 2).unwrap();

    // All addresses should be different
    assert_ne!(signer0.address(), signer1.address());
    assert_ne!(signer1.address(), signer2.address());
    assert_ne!(signer0.address(), signer2.address());

    // Each signer should produce valid signatures
    let tx = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build()
        .unwrap();

    for (i, signer) in [&signer0, &signer1, &signer2].iter().enumerate() {
        let sig = signer.sign_transaction(&tx).unwrap();
        let recovered = recover_signer(&tx.signing_hash(), &sig).unwrap();
        assert_eq!(
            recovered,
            signer.address(),
            "Recovery failed for signer {}",
            i
        );
    }
}

// ==================== Validation Tests ====================

#[test]
fn test_validation_max_fee_less_than_priority_fee() {
    let result = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(10)) // Higher than max_fee
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build();

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("max_fee_per_gas"));
}

#[test]
fn test_validation_gas_limit_too_low() {
    let result = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(20_000) // Below minimum 21,000
        .build();

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("21000") || err.contains("gas"));
}

#[test]
fn test_validation_missing_required_fields() {
    // Missing chain_id
    let result = Eip1559Transaction::builder()
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build();
    assert!(result.is_err());

    // Missing nonce
    let result = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build();
    assert!(result.is_err());

    // Missing gas fees
    let result = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .gas_limit(TRANSFER_GAS)
        .build();
    assert!(result.is_err());
}

// ==================== Chain ID Replay Protection Tests ====================

#[test]
fn test_different_chain_ids_produce_different_hashes() {
    let tx_mainnet = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build()
        .unwrap();

    let tx_testnet = Eip1559Transaction::builder()
        .chain_id(ChainId::BscTestnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build()
        .unwrap();

    // Different chain IDs should produce different signing hashes
    assert_ne!(tx_mainnet.signing_hash(), tx_testnet.signing_hash());
}

#[test]
fn test_signature_not_valid_on_different_chain() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();
    let signer = Bip44Signer::new(&account, 0).unwrap();

    // Sign on mainnet
    let tx_mainnet = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build()
        .unwrap();

    let signature = signer.sign_transaction(&tx_mainnet).unwrap();

    // Try to recover using testnet transaction hash
    let tx_testnet = Eip1559Transaction::builder()
        .chain_id(ChainId::BscTestnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build()
        .unwrap();

    // Recovery with wrong chain's hash should give different address
    let recovered = recover_signer(&tx_testnet.signing_hash(), &signature).unwrap();
    assert_ne!(recovered, signer.address());
}

// ==================== Address Derivation Tests ====================

#[test]
fn test_known_address_derivation() {
    // Known test vector: first address from standard test mnemonic
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();
    let signer = Bip44Signer::new(&account, 0).unwrap();

    // This is the known first address for the test mnemonic on m/44'/60'/0'/0/0
    let expected = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    assert_eq!(
        signer.address().to_checksum_string().to_lowercase(),
        expected.to_lowercase()
    );
}

// ==================== Transaction Type Tests ====================

#[test]
fn test_contract_creation_transaction() {
    let tx = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(100_000)
        // No `to` address = contract creation
        .data(vec![0x60, 0x80, 0x60, 0x40]) // Example bytecode
        .build()
        .unwrap();

    assert!(tx.is_contract_creation());
    assert!(!tx.is_transfer());
}

#[test]
fn test_simple_transfer_transaction() {
    let recipient: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        .parse()
        .unwrap();

    let tx = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .to(recipient)
        .value(Wei::from_ether(1))
        // No data = simple transfer
        .build()
        .unwrap();

    assert!(!tx.is_contract_creation());
    assert!(tx.is_transfer());
}

#[test]
fn test_contract_call_transaction() {
    let contract: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        .parse()
        .unwrap();

    let tx = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(65_000)
        .to(contract)
        .data(vec![0xa9, 0x05, 0x9c, 0xbb]) // transfer(address,uint256) selector
        .build()
        .unwrap();

    assert!(!tx.is_contract_creation());
    assert!(!tx.is_transfer()); // Has data, so not a simple transfer
}

// ==================== Determinism Tests ====================

#[test]
fn test_signing_is_deterministic() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();
    let signer = Bip44Signer::new(&account, 0).unwrap();

    let tx = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build()
        .unwrap();

    // Sign the same transaction multiple times
    let sig1 = signer.sign_transaction(&tx).unwrap();
    let sig2 = signer.sign_transaction(&tx).unwrap();
    let sig3 = signer.sign_transaction(&tx).unwrap();

    // RFC 6979 ensures deterministic signatures
    assert_eq!(sig1.r, sig2.r);
    assert_eq!(sig1.s, sig2.s);
    assert_eq!(sig2.r, sig3.r);
    assert_eq!(sig2.s, sig3.s);
}

#[test]
fn test_raw_transaction_is_deterministic() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();
    let signer = Bip44Signer::new(&account, 0).unwrap();

    let tx = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build()
        .unwrap();

    let sig = signer.sign_transaction(&tx).unwrap();
    let signed1 = SignedTransaction::new(tx.clone(), sig);
    let signed2 = SignedTransaction::new(tx, sig);

    assert_eq!(signed1.to_raw_transaction(), signed2.to_raw_transaction());
    assert_eq!(signed1.tx_hash(), signed2.tx_hash());
}
