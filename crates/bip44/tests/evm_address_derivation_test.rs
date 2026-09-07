//! Tests for EVM address derivation from BIP44 accounts.
//!
//! This test verifies that deriving addresses for EVM chains (Ethereum, BSC, etc.)
//! returns proper EVM addresses (0x...) instead of extended private keys (xprv...)
//! regardless of the Network parameter (BitcoinMainnet vs BitcoinTestnet).

use khodpay_bip32::Network;
use khodpay_bip44::{CoinType, Purpose, Wallet, Chain};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn test_bsc_mainnet_address_derivation() {
    // Create wallet from test mnemonic
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create wallet");

    // Get Ethereum account (BinanceCoin uses same derivation as Ethereum)
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get account");

    // Derive first external address
    let key = account
        .derive_external(0)
        .expect("Failed to derive external address");

    // Convert to EVM address
    let address = derive_evm_address_from_key(&key);

    // Should be a valid EVM address (starts with 0x, 42 chars total)
    assert!(address.starts_with("0x"), "Address should start with 0x");
    assert_eq!(address.len(), 42, "Address should be 42 characters");
    
    // Should NOT be an extended private key
    assert!(!address.starts_with("xprv"), "Should not return xprv format");
    assert!(!address.starts_with("tprv"), "Should not return tprv format");

    // Known address for this mnemonic and path
    let expected = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    assert_eq!(
        address.to_lowercase(),
        expected.to_lowercase(),
        "Address should match known test vector"
    );
}

#[test]
fn test_bsc_testnet_address_derivation() {
    // Create wallet from test mnemonic using BitcoinTestnet network
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinTestnet)
        .expect("Failed to create wallet");

    // Get Ethereum account (testnet uses same keys as mainnet for EVM)
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get account");

    // Derive first external address
    let key = account
        .derive_external(0)
        .expect("Failed to derive external address");

    // Convert to EVM address
    let address = derive_evm_address_from_key(&key);

    // Should be a valid EVM address (starts with 0x, 42 chars total)
    assert!(address.starts_with("0x"), "Address should start with 0x");
    assert_eq!(address.len(), 42, "Address should be 42 characters");
    
    // Should NOT be an extended private key
    assert!(!address.starts_with("xprv"), "Should not return xprv format");
    assert!(!address.starts_with("tprv"), "Should not return tprv format");

    // For EVM chains, mainnet and testnet use the same address
    let expected = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
    assert_eq!(
        address.to_lowercase(),
        expected.to_lowercase(),
        "Testnet should have same address as mainnet for EVM chains"
    );
}

#[test]
fn test_multiple_bsc_addresses() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create wallet");

    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get account");

    // Derive multiple addresses
    let addresses: Vec<String> = (0..5)
        .map(|i| {
            let key = account.derive_external(i).expect("Failed to derive");
            derive_evm_address_from_key(&key)
        })
        .collect();

    // All should be valid EVM addresses
    for (i, addr) in addresses.iter().enumerate() {
        assert!(addr.starts_with("0x"), "Address {} should start with 0x", i);
        assert_eq!(addr.len(), 42, "Address {} should be 42 characters", i);
        assert!(!addr.starts_with("xprv"), "Address {} should not be xprv", i);
    }

    // All addresses should be unique
    for i in 0..addresses.len() {
        for j in i + 1..addresses.len() {
            assert_ne!(
                addresses[i], addresses[j],
                "Addresses {} and {} should be different",
                i, j
            );
        }
    }
}

#[test]
fn test_internal_chain_address_derivation() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create wallet");

    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get account");

    // Derive internal (change) address
    let key = account
        .derive_internal(0)
        .expect("Failed to derive internal address");

    let address = derive_evm_address_from_key(&key);

    // Should be a valid EVM address
    assert!(address.starts_with("0x"), "Internal address should start with 0x");
    assert_eq!(address.len(), 42, "Internal address should be 42 characters");
    assert!(!address.starts_with("xprv"), "Internal address should not be xprv");
}

#[test]
fn test_derive_address_with_chain() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create wallet");

    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .expect("Failed to get account");

    // Derive using Chain enum
    let external_key = account
        .derive_address(Chain::External, 0)
        .expect("Failed to derive external");
    let internal_key = account
        .derive_address(Chain::Internal, 0)
        .expect("Failed to derive internal");

    let external_addr = derive_evm_address_from_key(&external_key);
    let internal_addr = derive_evm_address_from_key(&internal_key);

    // Both should be valid EVM addresses
    assert!(external_addr.starts_with("0x"));
    assert!(internal_addr.starts_with("0x"));
    assert_eq!(external_addr.len(), 42);
    assert_eq!(internal_addr.len(), 42);

    // External and internal addresses should be different
    assert_ne!(external_addr, internal_addr);
}

#[test]
fn test_binance_coin_type_address_derivation() {
    let mut wallet = Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet)
        .expect("Failed to create wallet");

    // Use BinanceCoin coin type explicitly
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::BinanceCoin, 0)
        .expect("Failed to get account");

    let key = account
        .derive_external(0)
        .expect("Failed to derive address");

    let address = derive_evm_address_from_key(&key);

    // Should be a valid EVM address
    assert!(address.starts_with("0x"), "BinanceCoin address should start with 0x");
    assert_eq!(address.len(), 42, "BinanceCoin address should be 42 characters");
    assert!(!address.starts_with("xprv"), "BinanceCoin address should not be xprv");
}

// Helper function to derive EVM address from extended private key
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
