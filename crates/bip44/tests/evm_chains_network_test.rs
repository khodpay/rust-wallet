//! Comprehensive tests for EVM chains (BSC, Polygon, Ethereum) with different Network parameters.
//!
//! This test suite verifies that EVM address derivation works correctly regardless of
//! whether the wallet is created with BitcoinMainnet or BitcoinTestnet network parameter.

use khodpay_bip32::Network;
use khodpay_bip44::{CoinType, Purpose, Wallet, Chain};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Expected address for m/44'/60'/0'/0/0 (Ethereum path)
const EXPECTED_ETH_ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

// ==================== Ethereum Tests ====================

#[test]
fn test_ethereum_with_bitcoin_mainnet_network() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create wallet");

    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get account");

    let key = account.derive_external(0).expect("Failed to derive");
    let address = derive_evm_address_from_key(&key);

    assert!(address.starts_with("0x"), "Should return EVM address, not private key");
    assert_eq!(address.len(), 42, "EVM address should be 42 characters");
    assert!(!address.starts_with("xprv"), "Should not return xprv format");
    assert_eq!(address.to_lowercase(), EXPECTED_ETH_ADDRESS.to_lowercase());
}

#[test]
fn test_ethereum_with_bitcoin_testnet_network() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinTestnet)
        .expect("Failed to create wallet");

    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get account");

    let key = account.derive_external(0).expect("Failed to derive");
    let address = derive_evm_address_from_key(&key);

    assert!(address.starts_with("0x"), "Should return EVM address, not private key");
    assert_eq!(address.len(), 42, "EVM address should be 42 characters");
    assert!(!address.starts_with("tprv"), "Should not return tprv format");
    // EVM addresses are the same regardless of Bitcoin network parameter
    assert_eq!(address.to_lowercase(), EXPECTED_ETH_ADDRESS.to_lowercase());
}

// ==================== BSC (Binance Smart Chain) Tests ====================

#[test]
fn test_bsc_with_bitcoin_mainnet_network() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create wallet");

    // BSC uses Ethereum coin type (60) for address derivation
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get account");

    let key = account.derive_external(0).expect("Failed to derive");
    let address = derive_evm_address_from_key(&key);

    assert!(address.starts_with("0x"), "BSC address should start with 0x");
    assert_eq!(address.len(), 42, "BSC address should be 42 characters");
    assert!(!address.starts_with("xprv"), "Should not return xprv format");
    assert_eq!(address.to_lowercase(), EXPECTED_ETH_ADDRESS.to_lowercase());
}

#[test]
fn test_bsc_with_bitcoin_testnet_network() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinTestnet)
        .expect("Failed to create wallet");

    // BSC uses Ethereum coin type (60) for address derivation
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get account");

    let key = account.derive_external(0).expect("Failed to derive");
    let address = derive_evm_address_from_key(&key);

    assert!(address.starts_with("0x"), "BSC address should start with 0x");
    assert_eq!(address.len(), 42, "BSC address should be 42 characters");
    assert!(!address.starts_with("tprv"), "Should not return tprv format");
    // BSC addresses are identical to Ethereum addresses (same derivation path)
    assert_eq!(address.to_lowercase(), EXPECTED_ETH_ADDRESS.to_lowercase());
}

#[test]
fn test_bsc_binance_coin_type_with_mainnet() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create wallet");

    // Using BinanceCoin coin type (714)
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::BinanceCoin, 0)
        .expect("Failed to get account");

    let key = account.derive_external(0).expect("Failed to derive");
    let address = derive_evm_address_from_key(&key);

    assert!(address.starts_with("0x"), "BinanceCoin address should start with 0x");
    assert_eq!(address.len(), 42, "BinanceCoin address should be 42 characters");
    assert!(!address.starts_with("xprv"), "Should not return xprv format");
}

#[test]
fn test_bsc_binance_coin_type_with_testnet() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinTestnet)
        .expect("Failed to create wallet");

    // Using BinanceCoin coin type (714)
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::BinanceCoin, 0)
        .expect("Failed to get account");

    let key = account.derive_external(0).expect("Failed to derive");
    let address = derive_evm_address_from_key(&key);

    assert!(address.starts_with("0x"), "BinanceCoin address should start with 0x");
    assert_eq!(address.len(), 42, "BinanceCoin address should be 42 characters");
    assert!(!address.starts_with("tprv"), "Should not return tprv format");
}

// ==================== Polygon Tests ====================

#[test]
fn test_polygon_with_bitcoin_mainnet_network() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create wallet");

    // Polygon uses Ethereum coin type (60) for address derivation
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get account");

    let key = account.derive_external(0).expect("Failed to derive");
    let address = derive_evm_address_from_key(&key);

    assert!(address.starts_with("0x"), "Polygon address should start with 0x");
    assert_eq!(address.len(), 42, "Polygon address should be 42 characters");
    assert!(!address.starts_with("xprv"), "Should not return xprv format");
    // Polygon uses same addresses as Ethereum
    assert_eq!(address.to_lowercase(), EXPECTED_ETH_ADDRESS.to_lowercase());
}

#[test]
fn test_polygon_with_bitcoin_testnet_network() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinTestnet)
        .expect("Failed to create wallet");

    // Polygon uses Ethereum coin type (60) for address derivation
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get account");

    let key = account.derive_external(0).expect("Failed to derive");
    let address = derive_evm_address_from_key(&key);

    assert!(address.starts_with("0x"), "Polygon address should start with 0x");
    assert_eq!(address.len(), 42, "Polygon address should be 42 characters");
    assert!(!address.starts_with("tprv"), "Should not return tprv format");
    // Polygon uses same addresses as Ethereum
    assert_eq!(address.to_lowercase(), EXPECTED_ETH_ADDRESS.to_lowercase());
}

// ==================== Ethereum Classic Tests ====================

#[test]
fn test_ethereum_classic_with_mainnet() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create wallet");

    let account = wallet
        .get_account(Purpose::BIP44, CoinType::EthereumClassic, 0)
        .expect("Failed to get account");

    let key = account.derive_external(0).expect("Failed to derive");
    let address = derive_evm_address_from_key(&key);

    assert!(address.starts_with("0x"), "ETC address should start with 0x");
    assert_eq!(address.len(), 42, "ETC address should be 42 characters");
    assert!(!address.starts_with("xprv"), "Should not return xprv format");
}

#[test]
fn test_ethereum_classic_with_testnet() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinTestnet)
        .expect("Failed to create wallet");

    let account = wallet
        .get_account(Purpose::BIP44, CoinType::EthereumClassic, 0)
        .expect("Failed to get account");

    let key = account.derive_external(0).expect("Failed to derive");
    let address = derive_evm_address_from_key(&key);

    assert!(address.starts_with("0x"), "ETC address should start with 0x");
    assert_eq!(address.len(), 42, "ETC address should be 42 characters");
    assert!(!address.starts_with("tprv"), "Should not return tprv format");
}

// ==================== Multiple Addresses Tests ====================

#[test]
fn test_multiple_addresses_mainnet_vs_testnet() {
    // Create wallets with different networks
    let mut wallet_mainnet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create mainnet wallet");
    let mut wallet_testnet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinTestnet)
        .expect("Failed to create testnet wallet");

    let account_mainnet = wallet_mainnet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get mainnet account");
    let account_testnet = wallet_testnet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get testnet account");

    // Derive multiple addresses from each
    for i in 0..5 {
        let key_mainnet = account_mainnet.derive_external(i).expect("Failed to derive mainnet");
        let key_testnet = account_testnet.derive_external(i).expect("Failed to derive testnet");

        let addr_mainnet = derive_evm_address_from_key(&key_mainnet);
        let addr_testnet = derive_evm_address_from_key(&key_testnet);

        // Both should be valid EVM addresses
        assert!(addr_mainnet.starts_with("0x"), "Mainnet address {} should start with 0x", i);
        assert!(addr_testnet.starts_with("0x"), "Testnet address {} should start with 0x", i);

        // Should not be private keys
        assert!(!addr_mainnet.starts_with("xprv"), "Mainnet address {} should not be xprv", i);
        assert!(!addr_testnet.starts_with("tprv"), "Testnet address {} should not be tprv", i);

        // EVM addresses should be identical regardless of Bitcoin network
        assert_eq!(
            addr_mainnet.to_lowercase(),
            addr_testnet.to_lowercase(),
            "Address {} should be same for mainnet and testnet",
            i
        );
    }
}

// ==================== Internal Chain Tests ====================

#[test]
fn test_internal_chain_with_both_networks() {
    let mut wallet_mainnet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create mainnet wallet");
    let mut wallet_testnet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinTestnet)
        .expect("Failed to create testnet wallet");

    let account_mainnet = wallet_mainnet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get mainnet account");
    let account_testnet = wallet_testnet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get testnet account");

    // Test internal (change) addresses
    let key_mainnet = account_mainnet.derive_internal(0).expect("Failed to derive mainnet internal");
    let key_testnet = account_testnet.derive_internal(0).expect("Failed to derive testnet internal");

    let addr_mainnet = derive_evm_address_from_key(&key_mainnet);
    let addr_testnet = derive_evm_address_from_key(&key_testnet);

    assert!(addr_mainnet.starts_with("0x"));
    assert!(addr_testnet.starts_with("0x"));
    assert!(!addr_mainnet.starts_with("xprv"));
    assert!(!addr_testnet.starts_with("tprv"));

    // Internal addresses should also be identical
    assert_eq!(addr_mainnet.to_lowercase(), addr_testnet.to_lowercase());
}

// ==================== Chain Enum Tests ====================

#[test]
fn test_derive_address_with_chain_enum() {
    let mut wallet_mainnet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create mainnet wallet");
    let mut wallet_testnet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinTestnet)
        .expect("Failed to create testnet wallet");

    let account_mainnet = wallet_mainnet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get mainnet account");
    let account_testnet = wallet_testnet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get testnet account");

    // Test with Chain enum
    for chain in [Chain::External, Chain::Internal] {
        let key_mainnet = account_mainnet.derive_address(chain, 0).expect("Failed to derive mainnet");
        let key_testnet = account_testnet.derive_address(chain, 0).expect("Failed to derive testnet");

        let addr_mainnet = derive_evm_address_from_key(&key_mainnet);
        let addr_testnet = derive_evm_address_from_key(&key_testnet);

        assert!(addr_mainnet.starts_with("0x"));
        assert!(addr_testnet.starts_with("0x"));
        assert_eq!(addr_mainnet.to_lowercase(), addr_testnet.to_lowercase());
    }
}

// ==================== Helper Function ====================

/// Helper function to derive EVM address from extended private key
fn derive_evm_address_from_key(key: &khodpay_bip32::ExtendedPrivateKey) -> String {
    use khodpay_signing::Address;
    
    // Get the uncompressed public key (65 bytes with 0x04 prefix)
    let public_key = key.private_key().public_key();
    let pubkey_uncompressed = public_key.serialize_uncompressed();
    
    // Skip the 0x04 prefix and derive EVM address from 64-byte public key
    let address = Address::from_public_key_bytes(&pubkey_uncompressed[1..])
        .expect("Failed to derive EVM address");
    
    address.to_checksum_string()
}
