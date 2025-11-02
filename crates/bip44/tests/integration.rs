//! Integration tests for BIP-44 with BIP-32 and BIP-39.
//!
//! These tests verify the complete workflow from mnemonic generation
//! through to address derivation, ensuring proper integration between
//! the BIP-39, BIP-32, and BIP-44 implementations.

use khodpay_bip32::{ChildNumber, ExtendedPrivateKey, Network};
use khodpay_bip39::{Language, Mnemonic};
use khodpay_bip44::{Account, Bip44Path, Chain, CoinType, Purpose, Wallet, WalletBuilder};

/// Test the complete workflow: mnemonic → seed → master key → BIP-44 paths → derived keys
#[test]
fn test_complete_workflow_mnemonic_to_addresses() {
    // Step 1: Create mnemonic (BIP-39)
    let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).unwrap();

    // Step 2: Generate seed from mnemonic (BIP-39)
    let seed = mnemonic.to_seed("").unwrap();

    // Step 3: Create master key from seed (BIP-32)
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

    // Step 4: Derive BIP-44 path manually (BIP-32 + BIP-44)
    // m/44'/0'/0'/0/0
    let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let external_key = account_key.derive_child(ChildNumber::Normal(0)).unwrap();
    let address_key = external_key.derive_child(ChildNumber::Normal(0)).unwrap();

    // Step 5: Verify using BIP-44 Account abstraction
    let account =
        Account::from_extended_key(account_key.clone(), Purpose::BIP44, CoinType::Bitcoin, 0);
    let derived = account.derive_address(Chain::External, 0).unwrap();

    // Keys should match
    assert_eq!(address_key.private_key(), derived.private_key());
    assert_eq!(address_key.chain_code(), derived.chain_code());
}

#[test]
fn test_wallet_from_mnemonic_integration() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Create wallet using BIP-44 Wallet abstraction
    let mut wallet =
        Wallet::from_mnemonic(mnemonic, "", Language::English, Network::BitcoinMainnet).unwrap();

    // Get account using BIP-44
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
        .unwrap();

    // Derive first receiving address
    let address = account.derive_external(0).unwrap();

    // Verify the key is valid
    assert_eq!(address.depth(), 5);
}

#[test]
fn test_wallet_builder_integration() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Use WalletBuilder for fluent API
    let mut wallet = WalletBuilder::new()
        .mnemonic(mnemonic)
        .network(Network::BitcoinMainnet)
        .build()
        .unwrap();

    // Derive Bitcoin account
    {
        let btc_account = wallet
            .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
            .unwrap();
        assert_eq!(btc_account.coin_type(), CoinType::Bitcoin);
    }

    // Derive Ethereum account
    {
        let eth_account = wallet
            .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
            .unwrap();
        assert_eq!(eth_account.coin_type(), CoinType::Ethereum);
    }
}

#[test]
fn test_multiple_accounts_same_coin() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    // Create multiple Bitcoin accounts and derive addresses
    let addr0 = {
        let account0 = wallet
            .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
            .unwrap();
        account0.derive_external(0).unwrap()
    };

    let addr1 = {
        let account1 = wallet
            .get_account(Purpose::BIP44, CoinType::Bitcoin, 1)
            .unwrap();
        account1.derive_external(0).unwrap()
    };

    let addr2 = {
        let account2 = wallet
            .get_account(Purpose::BIP44, CoinType::Bitcoin, 2)
            .unwrap();
        account2.derive_external(0).unwrap()
    };

    // All addresses should be different
    assert_ne!(addr0.private_key(), addr1.private_key());
    assert_ne!(addr1.private_key(), addr2.private_key());
    assert_ne!(addr0.private_key(), addr2.private_key());
}

#[test]
fn test_external_vs_internal_chains() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();

    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

    // Derive to account level
    let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();

    let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

    // Derive from both chains
    let external = account.derive_external(0).unwrap();
    let internal = account.derive_internal(0).unwrap();

    // Should be different keys
    assert_ne!(external.private_key(), internal.private_key());
}

#[test]
fn test_bip44_path_construction_and_derivation() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();

    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

    // Create BIP-44 path
    let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 5).unwrap();

    // Derive using path
    let derivation_path = path.to_derivation_path();
    let derived_key = master_key.derive_path(&derivation_path).unwrap();

    // Derive using Account abstraction
    let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);
    let account_derived = account.derive_external(5).unwrap();

    // Both methods should produce the same key
    assert_eq!(derived_key.private_key(), account_derived.private_key());
}

#[test]
fn test_different_bip_purposes() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    // Derive addresses from different BIP purposes
    let addr44 = {
        let account = wallet
            .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
            .unwrap();
        account.derive_external(0).unwrap()
    };

    let addr49 = {
        let account = wallet
            .get_account(Purpose::BIP49, CoinType::Bitcoin, 0)
            .unwrap();
        account.derive_external(0).unwrap()
    };

    let addr84 = {
        let account = wallet
            .get_account(Purpose::BIP84, CoinType::Bitcoin, 0)
            .unwrap();
        account.derive_external(0).unwrap()
    };

    let addr86 = {
        let account = wallet
            .get_account(Purpose::BIP86, CoinType::Bitcoin, 0)
            .unwrap();
        account.derive_external(0).unwrap()
    };

    // All should be different
    assert_ne!(addr44.private_key(), addr49.private_key());
    assert_ne!(addr49.private_key(), addr84.private_key());
    assert_ne!(addr84.private_key(), addr86.private_key());
}

#[test]
fn test_seed_vs_mnemonic_equivalence() {
    let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Create wallet from mnemonic
    let wallet1 =
        Wallet::from_english_mnemonic(mnemonic_phrase, "", Network::BitcoinMainnet).unwrap();

    // Create wallet from seed
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).unwrap();
    let seed = mnemonic.to_seed("").unwrap();
    let wallet2 = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();

    // Both wallets should produce the same master key
    assert_eq!(
        wallet1.master_key().private_key(),
        wallet2.master_key().private_key()
    );
    assert_eq!(
        wallet1.master_key().chain_code(),
        wallet2.master_key().chain_code()
    );
}

#[test]
fn test_password_protected_mnemonic() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = "my-secure-password";

    // Create wallet with password
    let wallet_with_pass =
        Wallet::from_english_mnemonic(mnemonic, password, Network::BitcoinMainnet).unwrap();

    // Create wallet without password
    let wallet_no_pass =
        Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    // Master keys should be different
    assert_ne!(
        wallet_with_pass.master_key().private_key(),
        wallet_no_pass.master_key().private_key()
    );
}

#[test]
fn test_multi_coin_wallet() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    // Derive addresses for different cryptocurrencies
    let btc_addr = {
        let btc = wallet
            .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
            .unwrap();
        btc.derive_external(0).unwrap()
    };

    let eth_addr = {
        let eth = wallet
            .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
            .unwrap();
        eth.derive_external(0).unwrap()
    };

    let ltc_addr = {
        let ltc = wallet
            .get_account(Purpose::BIP44, CoinType::Litecoin, 0)
            .unwrap();
        ltc.derive_external(0).unwrap()
    };

    // All should be different
    assert_ne!(btc_addr.private_key(), eth_addr.private_key());
    assert_ne!(eth_addr.private_key(), ltc_addr.private_key());
    assert_ne!(btc_addr.private_key(), ltc_addr.private_key());
}

#[test]
fn test_address_batch_derivation() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();

    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();

    // Derive to account level
    let purpose_key = master_key.derive_child(ChildNumber::Hardened(44)).unwrap();
    let coin_key = purpose_key.derive_child(ChildNumber::Hardened(0)).unwrap();
    let account_key = coin_key.derive_child(ChildNumber::Hardened(0)).unwrap();

    let account = Account::from_extended_key(account_key, Purpose::BIP44, CoinType::Bitcoin, 0);

    // Derive batch of addresses
    let addresses = account
        .derive_address_range(Chain::External, 0, 10)
        .unwrap();

    assert_eq!(addresses.len(), 10);

    // Verify each address individually
    for (i, addr) in addresses.iter().enumerate() {
        let individual = account.derive_external(i as u32).unwrap();
        assert_eq!(addr.private_key(), individual.private_key());
    }
}

#[test]
fn test_wallet_caching() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    assert_eq!(wallet.cached_account_count(), 0);

    // First access - should cache
    let _account1 = wallet
        .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
        .unwrap();
    assert_eq!(wallet.cached_account_count(), 1);

    // Second access - should use cache
    let _account2 = wallet
        .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
        .unwrap();
    assert_eq!(wallet.cached_account_count(), 1);

    // Different account - should cache new one
    let _account3 = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();
    assert_eq!(wallet.cached_account_count(), 2);

    // Clear cache
    wallet.clear_cache();
    assert_eq!(wallet.cached_account_count(), 0);
}

#[test]
fn test_testnet_vs_mainnet() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let mainnet_wallet =
        Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    let testnet_wallet =
        Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinTestnet).unwrap();

    // Master keys should be the same (network doesn't affect key derivation)
    assert_eq!(
        mainnet_wallet.master_key().private_key(),
        testnet_wallet.master_key().private_key()
    );

    // But networks should be different
    assert_eq!(mainnet_wallet.network(), Network::BitcoinMainnet);
    assert_eq!(testnet_wallet.network(), Network::BitcoinTestnet);
}

#[test]
fn test_large_address_indices() {
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

    // Derive addresses with large indices
    let addr_1000 = account.derive_external(1000).unwrap();
    let addr_10000 = account.derive_external(10000).unwrap();
    let addr_100000 = account.derive_external(100000).unwrap();

    // All should be valid and different
    assert_ne!(addr_1000.private_key(), addr_10000.private_key());
    assert_ne!(addr_10000.private_key(), addr_100000.private_key());
}

#[test]
fn test_path_string_representation() {
    let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 5).unwrap();

    // Verify string representation
    assert_eq!(path.to_string(), "m/44'/0'/0'/0/5");

    // Parse back
    let parsed: Bip44Path = "m/44'/0'/0'/0/5".parse().unwrap();
    assert_eq!(path, parsed);
}

#[test]
fn test_complete_workflow_with_builder() {
    // Complete workflow using builder pattern
    let mut wallet = WalletBuilder::new()
        .mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        .password("test-password")
        .language(Language::English)
        .network(Network::BitcoinMainnet)
        .build()
        .unwrap();

    // Get account
    let account = wallet
        .get_account(Purpose::BIP84, CoinType::Bitcoin, 0)
        .unwrap();

    // Derive receiving addresses
    let receive_addresses = account.derive_address_range(Chain::External, 0, 5).unwrap();
    assert_eq!(receive_addresses.len(), 5);

    // Derive change addresses
    let change_addresses = account.derive_address_range(Chain::Internal, 0, 5).unwrap();
    assert_eq!(change_addresses.len(), 5);

    // Verify they're all different
    for recv in &receive_addresses {
        for change in &change_addresses {
            assert_ne!(recv.private_key(), change.private_key());
        }
    }
}
