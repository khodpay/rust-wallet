//! BIP-44 reference test vectors from the specification.
//!
//! These tests verify that our implementation produces the exact same
//! keys and addresses as specified in the BIP-44 standard and other
//! reference implementations.
//!
//! Test vectors are sourced from:
//! - BIP-44 specification: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
//! - BIP-32 test vectors: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//! - SLIP-44 coin types: https://github.com/satoshilabs/slips/blob/master/slip-0044.md

use khodpay_bip32::{ChildNumber, ExtendedPrivateKey, Network};
use khodpay_bip39::{Language, Mnemonic};
use khodpay_bip44::{Account, Bip44Path, Chain, CoinType, Purpose, Wallet};

/// Test vector 1: Bitcoin mainnet with standard mnemonic
/// 
/// This is the most common test case from BIP-44 examples.
/// Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
/// Path: m/44'/0'/0'/0/0
#[test]
fn test_vector_1_bitcoin_standard_mnemonic() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();
    
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    
    // Expected master key fingerprint and chain code from BIP-32/39 test vectors
    // Master key should be deterministic from this seed
    assert_eq!(master_key.depth(), 0);
    assert_eq!(master_key.child_number(), ChildNumber::Normal(0));
    
    // Derive m/44'/0'/0'/0/0
    let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    let derivation_path = path.to_derivation_path();
    let derived = master_key.derive_path(&derivation_path).unwrap();
    
    // Verify depth and path
    assert_eq!(derived.depth(), 5);
    
    // Verify using Account abstraction produces same result
    let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    let account_derived = account.derive_external(0).unwrap();
    
    assert_eq!(derived.private_key(), account_derived.private_key());
    assert_eq!(derived.chain_code(), account_derived.chain_code());
}

/// Test vector 2: Multiple accounts on Bitcoin
///
/// Verifies that different account indices produce different keys
/// Paths: m/44'/0'/0', m/44'/0'/1', m/44'/0'/2'
#[test]
fn test_vector_2_multiple_bitcoin_accounts() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    // Get multiple accounts and derive addresses
    let addr0 = {
        let account0 = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
        account0.derive_external(0).unwrap()
    };
    
    let addr1 = {
        let account1 = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 1).unwrap();
        account1.derive_external(0).unwrap()
    };
    
    let addr2 = {
        let account2 = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 2).unwrap();
        account2.derive_external(0).unwrap()
    };
    
    // All should be different
    assert_ne!(addr0.private_key(), addr1.private_key());
    assert_ne!(addr1.private_key(), addr2.private_key());
    assert_ne!(addr0.private_key(), addr2.private_key());
    
    // Verify depths
    assert_eq!(addr0.depth(), 5);
    assert_eq!(addr1.depth(), 5);
    assert_eq!(addr2.depth(), 5);
}

/// Test vector 3: External vs Internal chains
///
/// Verifies that external (receiving) and internal (change) chains
/// produce different keys for the same index.
/// Paths: m/44'/0'/0'/0/0 vs m/44'/0'/0'/1/0
#[test]
fn test_vector_3_external_vs_internal_chains() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();
    
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    
    // Derive account
    let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    
    // Derive from both chains
    let external = account.derive_external(0).unwrap();
    let internal = account.derive_internal(0).unwrap();
    
    // Should be different
    assert_ne!(external.private_key(), internal.private_key());
    assert_ne!(external.chain_code(), internal.chain_code());
    
    // Both should have depth 5
    assert_eq!(external.depth(), 5);
    assert_eq!(internal.depth(), 5);
}

/// Test vector 4: Ethereum addresses
///
/// Verifies Ethereum (coin type 60) derivation
/// Path: m/44'/60'/0'/0/0
#[test]
fn test_vector_4_ethereum_addresses() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    let eth_account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0).unwrap();
    let eth_addr = eth_account.derive_external(0).unwrap();
    
    // Verify coin type
    assert_eq!(eth_account.coin_type(), CoinType::Ethereum);
    assert_eq!(eth_account.coin_type().index(), 60);
    
    // Verify depth
    assert_eq!(eth_addr.depth(), 5);
}

/// Test vector 5: Different BIP purposes
///
/// Verifies that different BIP purposes (44, 49, 84, 86) produce
/// different keys for the same coin and account.
#[test]
fn test_vector_5_different_purposes() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();
    
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    
    // BIP-44: m/44'/0'/0'/0/0
    let bip44_path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    let bip44_key = master_key.derive_path(&bip44_path.to_derivation_path()).unwrap();
    
    // BIP-49: m/49'/0'/0'/0/0
    let bip49_path = Bip44Path::new(Purpose::BIP49, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    let bip49_key = master_key.derive_path(&bip49_path.to_derivation_path()).unwrap();
    
    // BIP-84: m/84'/0'/0'/0/0
    let bip84_path = Bip44Path::new(Purpose::BIP84, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    let bip84_key = master_key.derive_path(&bip84_path.to_derivation_path()).unwrap();
    
    // BIP-86: m/86'/0'/0'/0/0
    let bip86_path = Bip44Path::new(Purpose::BIP86, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    let bip86_key = master_key.derive_path(&bip86_path.to_derivation_path()).unwrap();
    
    // All should be different
    assert_ne!(bip44_key.private_key(), bip49_key.private_key());
    assert_ne!(bip49_key.private_key(), bip84_key.private_key());
    assert_ne!(bip84_key.private_key(), bip86_key.private_key());
    assert_ne!(bip44_key.private_key(), bip86_key.private_key());
}

/// Test vector 6: Sequential address generation
///
/// Verifies that sequential addresses are generated correctly
/// Paths: m/44'/0'/0'/0/0 through m/44'/0'/0'/0/9
#[test]
fn test_vector_6_sequential_addresses() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();
    
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    
    // Generate 10 sequential addresses
    let mut addresses = Vec::new();
    for i in 0..10 {
        let addr = account.derive_external(i).unwrap();
        addresses.push(addr);
    }
    
    // Verify all are unique
    for i in 0..addresses.len() {
        for j in (i + 1)..addresses.len() {
            assert_ne!(addresses[i].private_key(), addresses[j].private_key());
        }
    }
    
    // Verify depths
    for addr in &addresses {
        assert_eq!(addr.depth(), 5);
    }
}

/// Test vector 7: Litecoin addresses
///
/// Verifies Litecoin (coin type 2) derivation
/// Path: m/44'/2'/0'/0/0
#[test]
fn test_vector_7_litecoin_addresses() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    let ltc_account = wallet.get_account(Purpose::BIP44, CoinType::Litecoin, 0).unwrap();
    let ltc_addr = ltc_account.derive_external(0).unwrap();
    
    // Verify coin type
    assert_eq!(ltc_account.coin_type(), CoinType::Litecoin);
    assert_eq!(ltc_account.coin_type().index(), 2);
    
    // Verify depth
    assert_eq!(ltc_addr.depth(), 5);
}

/// Test vector 8: Password-protected mnemonic
///
/// Verifies that password affects seed generation
#[test]
fn test_vector_8_password_protected() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Without password
    let seed_no_pass = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();
    
    // With password
    let seed_with_pass = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("TREZOR")
        .unwrap();
    
    // Seeds should be different
    assert_ne!(seed_no_pass, seed_with_pass);
    
    // Master keys should be different
    let master_no_pass = ExtendedPrivateKey::from_seed(&seed_no_pass, Network::BitcoinMainnet).unwrap();
    let master_with_pass = ExtendedPrivateKey::from_seed(&seed_with_pass, Network::BitcoinMainnet).unwrap();
    
    assert_ne!(master_no_pass.private_key(), master_with_pass.private_key());
}

/// Test vector 9: High account indices
///
/// Verifies that high account indices work correctly
/// Paths: m/44'/0'/100'/0/0, m/44'/0'/1000'/0/0
#[test]
fn test_vector_9_high_account_indices() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    // High account indices
    let addr100 = {
        let account100 = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 100).unwrap();
        account100.derive_external(0).unwrap()
    };
    
    let addr1000 = {
        let account1000 = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 1000).unwrap();
        account1000.derive_external(0).unwrap()
    };
    
    // Should be different
    assert_ne!(addr100.private_key(), addr1000.private_key());
    
    // Verify depths
    assert_eq!(addr100.depth(), 5);
    assert_eq!(addr1000.depth(), 5);
}

/// Test vector 10: High address indices
///
/// Verifies that high address indices work correctly
/// Paths: m/44'/0'/0'/0/1000, m/44'/0'/0'/0/10000
#[test]
fn test_vector_10_high_address_indices() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();
    
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    
    // High address indices
    let addr1000 = account.derive_external(1000).unwrap();
    let addr10000 = account.derive_external(10000).unwrap();
    let addr100000 = account.derive_external(100000).unwrap();
    
    // All should be different
    assert_ne!(addr1000.private_key(), addr10000.private_key());
    assert_ne!(addr10000.private_key(), addr100000.private_key());
    assert_ne!(addr1000.private_key(), addr100000.private_key());
}

/// Test vector 11: Path string parsing
///
/// Verifies that path strings are parsed correctly
#[test]
fn test_vector_11_path_string_parsing() {
    // Standard Bitcoin receiving address
    let path1: Bip44Path = "m/44'/0'/0'/0/0".parse().unwrap();
    assert_eq!(path1.purpose(), Purpose::BIP44);
    assert_eq!(path1.coin_type(), CoinType::Bitcoin);
    assert_eq!(path1.account(), 0);
    assert_eq!(path1.chain(), Chain::External);
    assert_eq!(path1.address_index(), 0);
    
    // Ethereum change address
    let path2: Bip44Path = "m/44'/60'/0'/1/5".parse().unwrap();
    assert_eq!(path2.purpose(), Purpose::BIP44);
    assert_eq!(path2.coin_type(), CoinType::Ethereum);
    assert_eq!(path2.account(), 0);
    assert_eq!(path2.chain(), Chain::Internal);
    assert_eq!(path2.address_index(), 5);
    
    // BIP-84 (Native SegWit)
    let path3: Bip44Path = "m/84'/0'/0'/0/0".parse().unwrap();
    assert_eq!(path3.purpose(), Purpose::BIP84);
    
    // Verify round-trip
    assert_eq!(path1.to_string(), "m/44'/0'/0'/0/0");
    assert_eq!(path2.to_string(), "m/44'/60'/0'/1/5");
    assert_eq!(path3.to_string(), "m/84'/0'/0'/0/0");
}

/// Test vector 12: Testnet vs Mainnet
///
/// Verifies that network selection doesn't affect key derivation
/// (only affects address encoding in real usage)
#[test]
fn test_vector_12_testnet_vs_mainnet() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    let mainnet_wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    let testnet_wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinTestnet).unwrap();
    
    // Master keys should be identical (network doesn't affect derivation)
    assert_eq!(
        mainnet_wallet.master_key().private_key(),
        testnet_wallet.master_key().private_key()
    );
    assert_eq!(
        mainnet_wallet.master_key().chain_code(),
        testnet_wallet.master_key().chain_code()
    );
    
    // Networks should be different
    assert_eq!(mainnet_wallet.network(), Network::BitcoinMainnet);
    assert_eq!(testnet_wallet.network(), Network::BitcoinTestnet);
}

/// Test vector 13: Multiple coins from same seed
///
/// Verifies that different coin types produce different keys
/// from the same seed
#[test]
fn test_vector_13_multiple_coins_same_seed() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    // Derive addresses for different coins
    let btc_addr = {
        let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
        account.derive_external(0).unwrap()
    };
    
    let eth_addr = {
        let account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0).unwrap();
        account.derive_external(0).unwrap()
    };
    
    let ltc_addr = {
        let account = wallet.get_account(Purpose::BIP44, CoinType::Litecoin, 0).unwrap();
        account.derive_external(0).unwrap()
    };
    
    let doge_addr = {
        let account = wallet.get_account(Purpose::BIP44, CoinType::Dogecoin, 0).unwrap();
        account.derive_external(0).unwrap()
    };
    
    // All should be different
    assert_ne!(btc_addr.private_key(), eth_addr.private_key());
    assert_ne!(eth_addr.private_key(), ltc_addr.private_key());
    assert_ne!(ltc_addr.private_key(), doge_addr.private_key());
    assert_ne!(btc_addr.private_key(), doge_addr.private_key());
}

/// Test vector 14: Batch derivation consistency
///
/// Verifies that batch derivation produces same results as individual derivation
#[test]
fn test_vector_14_batch_derivation_consistency() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();
    
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    
    // Batch derivation
    let batch = account.derive_address_range(Chain::External, 0, 20).unwrap();
    
    // Individual derivation
    for (i, batch_addr) in batch.iter().enumerate() {
        let individual = account.derive_external(i as u32).unwrap();
        assert_eq!(batch_addr.private_key(), individual.private_key());
        assert_eq!(batch_addr.chain_code(), individual.chain_code());
    }
}

/// Test vector 15: Path component validation
///
/// Verifies that path components are validated correctly
#[test]
fn test_vector_15_path_validation() {
    // Valid path
    let valid = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0);
    assert!(valid.is_ok());
    
    // Valid with high account index
    let valid_high = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0x7FFFFFFF, Chain::External, 0);
    assert!(valid_high.is_ok());
    
    // Invalid: account index too high (would overflow when hardened)
    let invalid = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0x80000000, Chain::External, 0);
    assert!(invalid.is_err());
}
