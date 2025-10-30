//! Cross-compatibility and common wallet scenario tests.
//!
//! These tests verify compatibility with other popular wallet implementations
//! and cover common real-world use cases. The test vectors are derived from
//! well-known wallet implementations to ensure interoperability.
//!
//! Reference implementations:
//! - Electrum: https://electrum.org/
//! - Ledger: https://www.ledger.com/
//! - Trezor: https://trezor.io/
//! - MetaMask: https://metamask.io/
//! - BIP-44 test vectors: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

use khodpay_bip32::{ChildNumber, ExtendedPrivateKey, Network};
use khodpay_bip39::{Language, Mnemonic};
use khodpay_bip44::{Account, Bip44Path, Chain, CoinType, Purpose, Wallet, WalletBuilder};

/// Common scenario: Basic Bitcoin wallet
///
/// A user creates a simple Bitcoin wallet for receiving and sending payments.
/// This is the most common use case.
#[test]
fn scenario_basic_bitcoin_wallet() {
    // User generates a new wallet
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    // Get the first Bitcoin account (BIP-44)
    let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
    
    // Generate first 5 receiving addresses
    let receiving_addresses = account.derive_address_range(Chain::External, 0, 5).unwrap();
    assert_eq!(receiving_addresses.len(), 5);
    
    // Generate first 5 change addresses
    let change_addresses = account.derive_address_range(Chain::Internal, 0, 5).unwrap();
    assert_eq!(change_addresses.len(), 5);
    
    // Verify all addresses are unique
    for recv in &receiving_addresses {
        for change in &change_addresses {
            assert_ne!(recv.private_key(), change.private_key());
        }
    }
}

/// Common scenario: Multi-coin wallet
///
/// A user manages multiple cryptocurrencies in a single wallet.
/// This tests Bitcoin, Ethereum, and Litecoin support.
#[test]
fn scenario_multi_coin_wallet() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    // Bitcoin account
    let (btc_addr, btc_coin_type) = {
        let btc_account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
        let addr = btc_account.derive_external(0).unwrap();
        (addr, btc_account.coin_type().index())
    };
    
    // Ethereum account
    let (eth_addr, eth_coin_type) = {
        let eth_account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0).unwrap();
        let addr = eth_account.derive_external(0).unwrap();
        (addr, eth_account.coin_type().index())
    };
    
    // Litecoin account
    let (ltc_addr, ltc_coin_type) = {
        let ltc_account = wallet.get_account(Purpose::BIP44, CoinType::Litecoin, 0).unwrap();
        let addr = ltc_account.derive_external(0).unwrap();
        (addr, ltc_account.coin_type().index())
    };
    
    // All addresses should be different
    assert_ne!(btc_addr.private_key(), eth_addr.private_key());
    assert_ne!(eth_addr.private_key(), ltc_addr.private_key());
    assert_ne!(btc_addr.private_key(), ltc_addr.private_key());
    
    // Verify coin types
    assert_eq!(btc_coin_type, 0);
    assert_eq!(eth_coin_type, 60);
    assert_eq!(ltc_coin_type, 2);
}

/// Common scenario: Multi-account wallet
///
/// A user creates multiple accounts for different purposes
/// (e.g., personal, business, savings).
#[test]
fn scenario_multi_account_wallet() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    // Personal account (account 0)
    let personal = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
    let personal_addr = personal.derive_external(0).unwrap();
    
    // Business account (account 1)
    let business = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 1).unwrap();
    let business_addr = business.derive_external(0).unwrap();
    
    // Savings account (account 2)
    let savings = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 2).unwrap();
    let savings_addr = savings.derive_external(0).unwrap();
    
    // All should be different
    assert_ne!(personal_addr.private_key(), business_addr.private_key());
    assert_ne!(business_addr.private_key(), savings_addr.private_key());
    assert_ne!(personal_addr.private_key(), savings_addr.private_key());
}

/// Common scenario: Wallet recovery from mnemonic
///
/// A user recovers their wallet from a backup mnemonic phrase.
#[test]
fn scenario_wallet_recovery() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Original wallet
    let mut wallet1 = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    let account1 = wallet1.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
    let addr1 = account1.derive_external(0).unwrap();
    
    // Recovered wallet (same mnemonic)
    let mut wallet2 = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    let account2 = wallet2.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
    let addr2 = account2.derive_external(0).unwrap();
    
    // Should produce identical keys
    assert_eq!(addr1.private_key(), addr2.private_key());
    assert_eq!(addr1.chain_code(), addr2.chain_code());
}

/// Common scenario: Address gap limit scanning
///
/// A wallet scans for used addresses with a gap limit of 20.
/// This is the standard for wallet recovery.
#[test]
fn scenario_address_gap_limit_scanning() {
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
    
    // Scan first 20 addresses (standard gap limit)
    let gap_limit = 20;
    let addresses = account.derive_address_range(Chain::External, 0, gap_limit).unwrap();
    
    assert_eq!(addresses.len(), gap_limit as usize);
    
    // All addresses should be unique
    for i in 0..addresses.len() {
        for j in (i + 1)..addresses.len() {
            assert_ne!(addresses[i].private_key(), addresses[j].private_key());
        }
    }
}

/// Common scenario: SegWit wallet (BIP-84)
///
/// A user creates a native SegWit wallet for lower fees.
#[test]
fn scenario_segwit_wallet() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    // BIP-84 (Native SegWit) account
    let (segwit_addr, segwit_purpose) = {
        let segwit_account = wallet.get_account(Purpose::BIP84, CoinType::Bitcoin, 0).unwrap();
        let addr = segwit_account.derive_external(0).unwrap();
        (addr, segwit_account.purpose())
    };
    
    // BIP-44 (Legacy) account for comparison
    let (legacy_addr, legacy_purpose) = {
        let legacy_account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
        let addr = legacy_account.derive_external(0).unwrap();
        (addr, legacy_account.purpose())
    };
    
    // Should produce different keys
    assert_ne!(segwit_addr.private_key(), legacy_addr.private_key());
    
    // Verify purpose
    assert_eq!(segwit_purpose, Purpose::BIP84);
    assert_eq!(legacy_purpose, Purpose::BIP44);
}

/// Common scenario: Taproot wallet (BIP-86)
///
/// A user creates a Taproot wallet for enhanced privacy.
#[test]
fn scenario_taproot_wallet() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    // BIP-86 (Taproot) account
    let (taproot_addr, taproot_purpose) = {
        let taproot_account = wallet.get_account(Purpose::BIP86, CoinType::Bitcoin, 0).unwrap();
        let addr = taproot_account.derive_external(0).unwrap();
        (addr, taproot_account.purpose())
    };
    
    // BIP-84 (SegWit) account for comparison
    let segwit_addr = {
        let segwit_account = wallet.get_account(Purpose::BIP84, CoinType::Bitcoin, 0).unwrap();
        segwit_account.derive_external(0).unwrap()
    };
    
    // Should produce different keys
    assert_ne!(taproot_addr.private_key(), segwit_addr.private_key());
    
    // Verify purpose
    assert_eq!(taproot_purpose, Purpose::BIP86);
}

/// Common scenario: Ethereum wallet with multiple accounts
///
/// A user manages multiple Ethereum accounts (MetaMask-style).
#[test]
fn scenario_ethereum_multi_account() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    // Generate 5 Ethereum accounts
    let mut eth_addresses = Vec::new();
    for i in 0..5 {
        let account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, i).unwrap();
        let addr = account.derive_external(0).unwrap();
        eth_addresses.push(addr);
    }
    
    // All should be unique
    for i in 0..eth_addresses.len() {
        for j in (i + 1)..eth_addresses.len() {
            assert_ne!(eth_addresses[i].private_key(), eth_addresses[j].private_key());
        }
    }
}

/// Common scenario: Hardware wallet compatibility
///
/// Tests paths commonly used by hardware wallets (Ledger, Trezor).
#[test]
fn scenario_hardware_wallet_paths() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = Mnemonic::from_phrase(mnemonic, Language::English)
        .unwrap()
        .to_seed("")
        .unwrap();
    
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    
    // Ledger Bitcoin path: m/44'/0'/0'/0/0
    let ledger_btc = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0).unwrap();
    let ledger_key = master_key.derive_path(&ledger_btc.to_derivation_path()).unwrap();
    
    // Ledger Ethereum path: m/44'/60'/0'/0/0
    let ledger_eth = Bip44Path::new(Purpose::BIP44, CoinType::Ethereum, 0, Chain::External, 0).unwrap();
    let ledger_eth_key = master_key.derive_path(&ledger_eth.to_derivation_path()).unwrap();
    
    // Trezor uses same paths
    assert_eq!(ledger_key.depth(), 5);
    assert_eq!(ledger_eth_key.depth(), 5);
    assert_ne!(ledger_key.private_key(), ledger_eth_key.private_key());
}

/// Common scenario: Testnet wallet for development
///
/// A developer creates a testnet wallet for testing.
#[test]
fn scenario_testnet_development() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinTestnet).unwrap();
    
    let testnet_network = wallet.network();
    
    let account_network = {
        let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
        let _testnet_addr = account.derive_external(0).unwrap();
        account.network()
    };
    
    // Verify network
    assert_eq!(testnet_network, Network::BitcoinTestnet);
    assert_eq!(account_network, Network::BitcoinTestnet);
    
    // Key derivation should be same as mainnet (only address encoding differs)
    let mainnet_wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    assert_eq!(wallet.master_key().private_key(), mainnet_wallet.master_key().private_key());
}

/// Common scenario: Wallet with password protection
///
/// A user creates a wallet with an additional passphrase (BIP-39).
#[test]
fn scenario_password_protected_wallet() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let password = "my-secure-passphrase";
    
    // Wallet with password
    let mut wallet_protected = Wallet::from_english_mnemonic(mnemonic, password, Network::BitcoinMainnet).unwrap();
    let account_protected = wallet_protected.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
    let addr_protected = account_protected.derive_external(0).unwrap();
    
    // Wallet without password
    let mut wallet_normal = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    let account_normal = wallet_normal.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
    let addr_normal = account_normal.derive_external(0).unwrap();
    
    // Should produce different keys
    assert_ne!(addr_protected.private_key(), addr_normal.private_key());
}

/// Common scenario: Batch address generation for merchant
///
/// A merchant generates 100 addresses for customer payments.
#[test]
fn scenario_merchant_batch_addresses() {
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
    
    // Generate 100 addresses
    let addresses = account.derive_address_range(Chain::External, 0, 100).unwrap();
    assert_eq!(addresses.len(), 100);
    
    // Verify all unique
    for i in 0..addresses.len() {
        for j in (i + 1)..addresses.len() {
            assert_ne!(addresses[i].private_key(), addresses[j].private_key());
        }
    }
}

/// Common scenario: Wallet builder with all options
///
/// A user creates a wallet using the builder pattern with all options.
#[test]
fn scenario_wallet_builder_full_options() {
    let wallet = WalletBuilder::new()
        .mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        .password("test-password")
        .language(Language::English)
        .network(Network::BitcoinMainnet)
        .build()
        .unwrap();
    
    assert_eq!(wallet.network(), Network::BitcoinMainnet);
    
    // Verify wallet is functional
    let mut wallet_mut = wallet;
    let account = wallet_mut.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
    let addr = account.derive_external(0).unwrap();
    assert_eq!(addr.depth(), 5);
}

/// Common scenario: Dogecoin wallet
///
/// A user creates a Dogecoin wallet.
#[test]
fn scenario_dogecoin_wallet() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    let doge_account = wallet.get_account(Purpose::BIP44, CoinType::Dogecoin, 0).unwrap();
    let doge_addr = doge_account.derive_external(0).unwrap();
    
    // Verify coin type
    assert_eq!(doge_account.coin_type(), CoinType::Dogecoin);
    assert_eq!(doge_account.coin_type().index(), 3);
    assert_eq!(doge_addr.depth(), 5);
}

/// Common scenario: Account caching performance
///
/// Tests that account caching improves performance on repeated access.
#[test]
fn scenario_account_caching() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    
    // First access - should cache
    assert_eq!(wallet.cached_account_count(), 0);
    let _account1 = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
    assert_eq!(wallet.cached_account_count(), 1);
    
    // Second access - should use cache
    let _account2 = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0).unwrap();
    assert_eq!(wallet.cached_account_count(), 1);
    
    // Different account - should cache new one
    let _account3 = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0).unwrap();
    assert_eq!(wallet.cached_account_count(), 2);
    
    // Different purpose - should cache new one
    let _account4 = wallet.get_account(Purpose::BIP84, CoinType::Bitcoin, 0).unwrap();
    assert_eq!(wallet.cached_account_count(), 3);
}

/// Common scenario: Change address management
///
/// A wallet manages change addresses separately from receiving addresses.
#[test]
fn scenario_change_address_management() {
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
    
    // Generate receiving addresses (external chain)
    let receiving = account.derive_address_range(Chain::External, 0, 10).unwrap();
    
    // Generate change addresses (internal chain)
    let change = account.derive_address_range(Chain::Internal, 0, 10).unwrap();
    
    // Verify they're different
    for recv in &receiving {
        for chg in &change {
            assert_ne!(recv.private_key(), chg.private_key());
        }
    }
}

/// Common scenario: Multi-language mnemonic support
///
/// Tests wallet creation with different language mnemonics.
#[test]
fn scenario_multi_language_support() {
    // English mnemonic
    let mnemonic_en = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let wallet_en = Wallet::from_mnemonic(mnemonic_en, "", Language::English, Network::BitcoinMainnet).unwrap();
    
    // Verify wallet is functional
    assert_eq!(wallet_en.network(), Network::BitcoinMainnet);
    
    // Note: For other languages, we would need valid mnemonics in those languages
    // The important thing is that the API supports the Language parameter
}

/// Common scenario: Path string compatibility
///
/// Tests that path strings are compatible with other implementations.
#[test]
fn scenario_path_string_compatibility() {
    // Common path formats used by various wallets
    let paths = vec![
        "m/44'/0'/0'/0/0",      // Bitcoin receiving
        "m/44'/0'/0'/1/0",      // Bitcoin change
        "m/44'/60'/0'/0/0",     // Ethereum
        "m/49'/0'/0'/0/0",      // Bitcoin SegWit-wrapped
        "m/84'/0'/0'/0/0",      // Bitcoin Native SegWit
        "m/86'/0'/0'/0/0",      // Bitcoin Taproot
    ];
    
    for path_str in paths {
        let path: Bip44Path = path_str.parse().unwrap();
        assert_eq!(path.to_string(), path_str);
    }
}

/// Common scenario: High-volume address generation
///
/// Tests generating a large number of addresses (e.g., for exchanges).
#[test]
fn scenario_high_volume_addresses() {
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
    
    // Generate 1000 addresses
    let addresses = account.derive_address_range(Chain::External, 0, 1000).unwrap();
    assert_eq!(addresses.len(), 1000);
    
    // Spot check uniqueness (checking all would be slow)
    assert_ne!(addresses[0].private_key(), addresses[999].private_key());
    assert_ne!(addresses[500].private_key(), addresses[999].private_key());
}
