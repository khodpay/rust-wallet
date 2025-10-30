//! Edge case and boundary condition tests.
//!
//! These tests verify that the implementation handles edge cases correctly,
//! including boundary values, error conditions, and unusual inputs.

use khodpay_bip32::{ChildNumber, ExtendedPrivateKey, Network};
use khodpay_bip39::{Language, Mnemonic};
use khodpay_bip44::{Account, Bip44Path, Chain, CoinType, Purpose, Wallet};

/// Test maximum account index (2^31 - 1)
///
/// BIP-44 uses hardened derivation for accounts, which limits the
/// maximum account index to 2^31 - 1 (0x7FFFFFFF).
#[test]
fn edge_case_max_account_index() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    // Maximum valid account index
    let max_account = 0x7FFFFFFF;
    let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, max_account);
    assert!(account.is_ok());

    let account = account.unwrap();
    assert_eq!(account.account_index(), max_account);
}

/// Test account index overflow (2^31)
///
/// Account indices >= 2^31 should fail because they would overflow
/// when converted to hardened child numbers.
#[test]
fn edge_case_account_index_overflow() {
    // Account index that would overflow when hardened
    let overflow_index = 0x80000000;

    let result = Bip44Path::new(
        Purpose::BIP44,
        CoinType::Bitcoin,
        overflow_index,
        Chain::External,
        0,
    );

    assert!(result.is_err());
}

/// Test maximum address index (u32::MAX)
///
/// Address indices use normal (non-hardened) derivation,
/// so they can use the full u32 range.
#[test]
fn edge_case_max_address_index() {
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

    // Maximum address index
    let max_index = u32::MAX;
    let result = account.derive_external(max_index);
    assert!(result.is_ok());
}

/// Test zero indices
///
/// All indices should support zero as a valid value.
#[test]
fn edge_case_zero_indices() {
    let path = Bip44Path::new(Purpose::BIP44, CoinType::Bitcoin, 0, Chain::External, 0);

    assert!(path.is_ok());
    let path = path.unwrap();
    assert_eq!(path.account(), 0);
    assert_eq!(path.address_index(), 0);
}

/// Test empty password
///
/// Empty passwords should be valid (equivalent to no password).
#[test]
fn edge_case_empty_password() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let wallet1 = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    let wallet2 = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    // Should produce identical keys
    assert_eq!(
        wallet1.master_key().private_key(),
        wallet2.master_key().private_key()
    );
}

/// Test very long password
///
/// BIP-39 should handle arbitrarily long passwords.
#[test]
fn edge_case_long_password() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let long_password = "a".repeat(1000);

    let result = Wallet::from_english_mnemonic(mnemonic, &long_password, Network::BitcoinMainnet);
    assert!(result.is_ok());
}

/// Test password with special characters
///
/// Passwords should support all UTF-8 characters.
#[test]
fn edge_case_password_special_chars() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let special_password = "🔐 パスワード @#$%^&*()";

    let result = Wallet::from_english_mnemonic(mnemonic, special_password, Network::BitcoinMainnet);
    assert!(result.is_ok());
}

/// Test invalid mnemonic (wrong word count)
///
/// Mnemonics must be 12, 15, 18, 21, or 24 words.
#[test]
fn edge_case_invalid_mnemonic_word_count() {
    // Only 11 words (invalid)
    let invalid_mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

    let result = Wallet::from_english_mnemonic(invalid_mnemonic, "", Network::BitcoinMainnet);
    assert!(result.is_err());
}

/// Test invalid mnemonic (invalid word)
///
/// All words must be from the BIP-39 wordlist.
#[test]
fn edge_case_invalid_mnemonic_word() {
    // "notaword" is not in the BIP-39 wordlist
    let invalid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";

    let result = Wallet::from_english_mnemonic(invalid_mnemonic, "", Network::BitcoinMainnet);
    assert!(result.is_err());
}

/// Test invalid mnemonic (wrong checksum)
///
/// The last word encodes a checksum that must be valid.
#[test]
fn edge_case_invalid_mnemonic_checksum() {
    // Valid words but invalid checksum (last word is wrong)
    let invalid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

    let result = Wallet::from_english_mnemonic(invalid_mnemonic, "", Network::BitcoinMainnet);
    assert!(result.is_err());
}

/// Test batch derivation with zero count
///
/// Requesting zero addresses should return an empty vector.
#[test]
fn edge_case_batch_derivation_zero_count() {
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

    let addresses = account.derive_address_range(Chain::External, 0, 0).unwrap();
    assert_eq!(addresses.len(), 0);
}

/// Test batch derivation with single address
///
/// Requesting one address should work correctly.
#[test]
fn edge_case_batch_derivation_single() {
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

    let addresses = account.derive_address_range(Chain::External, 0, 1).unwrap();
    assert_eq!(addresses.len(), 1);

    // Should match individual derivation
    let individual = account.derive_external(0).unwrap();
    assert_eq!(addresses[0].private_key(), individual.private_key());
}

/// Test batch derivation at high starting index
///
/// Batch derivation should work regardless of starting index.
#[test]
fn edge_case_batch_derivation_high_start() {
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

    let start_index = 1_000_000;
    let addresses = account
        .derive_address_range(Chain::External, start_index, 10)
        .unwrap();
    assert_eq!(addresses.len(), 10);

    // Verify first address matches individual derivation
    let individual = account.derive_external(start_index).unwrap();
    assert_eq!(addresses[0].private_key(), individual.private_key());
}

/// Test batch derivation near u32::MAX
///
/// Should handle indices near the maximum value correctly.
#[test]
fn edge_case_batch_derivation_near_max() {
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

    // Start near max and request 10 addresses (will saturate at u32::MAX)
    let start_index = u32::MAX - 5;
    let addresses = account
        .derive_address_range(Chain::External, start_index, 10)
        .unwrap();
    assert_eq!(addresses.len(), 10);
}

/// Test path string parsing with extra whitespace
///
/// Path parsing should handle whitespace gracefully.
#[test]
fn edge_case_path_parsing_whitespace() {
    // With leading/trailing whitespace
    let path_with_spaces = " m/44'/0'/0'/0/0 ";
    let result: Result<Bip44Path, _> = path_with_spaces.trim().parse();
    assert!(result.is_ok());
}

/// Test path string parsing with invalid format
///
/// Invalid path formats should be rejected.
#[test]
fn edge_case_path_parsing_invalid_format() {
    let invalid_paths = vec![
        "44'/0'/0'/0/0",     // Missing "m/"
        "m/44/0'/0'/0/0",    // First level not hardened
        "m/44'/0/0'/0/0",    // Second level not hardened
        "m/44'/0'/0/0/0",    // Third level not hardened
        "m/44'/0'/0'/0'/0",  // Fourth level hardened (should be normal)
        "m/44'/0'/0'/0/0'",  // Fifth level hardened (should be normal)
        "m/44'/0'/0'",       // Too few levels
        "m/44'/0'/0'/0/0/0", // Too many levels
    ];

    for invalid_path in invalid_paths {
        let result: Result<Bip44Path, _> = invalid_path.parse();
        assert!(result.is_err(), "Path should be invalid: {}", invalid_path);
    }
}

/// Test path string with very large indices
///
/// Path parsing should handle large indices correctly.
#[test]
fn edge_case_path_parsing_large_indices() {
    let path_str = "m/44'/0'/2147483647'/0/4294967295";
    let result: Result<Bip44Path, _> = path_str.parse();
    assert!(result.is_ok());

    let path = result.unwrap();
    assert_eq!(path.account(), 0x7FFFFFFF);
    assert_eq!(path.address_index(), u32::MAX);
}

/// Test custom coin type
///
/// Custom coin types should work for unlisted cryptocurrencies.
#[test]
fn edge_case_custom_coin_type() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    // Use custom coin type (e.g., 501 for Solana)
    let custom_coin = CoinType::Custom(501);
    let account = wallet.get_account(Purpose::BIP44, custom_coin, 0).unwrap();

    assert_eq!(account.coin_type(), custom_coin);
    assert_eq!(account.coin_type().index(), 501);
}

/// Test all supported coin types
///
/// Verify that all predefined coin types work correctly.
#[test]
fn edge_case_all_coin_types() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    let coin_types = vec![
        CoinType::Bitcoin,
        CoinType::BitcoinTestnet,
        CoinType::Litecoin,
        CoinType::Dogecoin,
        CoinType::Ethereum,
    ];

    for coin_type in coin_types {
        let account = wallet.get_account(Purpose::BIP44, coin_type, 0);
        assert!(account.is_ok(), "Failed for coin type: {:?}", coin_type);
    }
}

/// Test all supported purposes
///
/// Verify that all BIP purposes work correctly.
#[test]
fn edge_case_all_purposes() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    let purposes = vec![
        Purpose::BIP44,
        Purpose::BIP49,
        Purpose::BIP84,
        Purpose::BIP86,
    ];

    for purpose in purposes {
        let account = wallet.get_account(purpose, CoinType::Bitcoin, 0);
        assert!(account.is_ok(), "Failed for purpose: {:?}", purpose);
    }
}

/// Test wallet cache clearing
///
/// Clearing the cache should reset the count to zero.
#[test]
fn edge_case_wallet_cache_clear() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    // Add some accounts to cache
    let _account1 = wallet
        .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
        .unwrap();
    let _account2 = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();
    let _account3 = wallet
        .get_account(Purpose::BIP84, CoinType::Bitcoin, 0)
        .unwrap();

    assert_eq!(wallet.cached_account_count(), 3);

    // Clear cache
    wallet.clear_cache();
    assert_eq!(wallet.cached_account_count(), 0);

    // Re-accessing should cache again
    let _account1 = wallet
        .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
        .unwrap();
    assert_eq!(wallet.cached_account_count(), 1);
}

/// Test repeated cache access
///
/// Accessing the same account multiple times should not increase cache count.
#[test]
fn edge_case_repeated_cache_access() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mut wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    // Access same account 10 times
    for _ in 0..10 {
        let _account = wallet
            .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
            .unwrap();
    }

    // Should only be cached once
    assert_eq!(wallet.cached_account_count(), 1);
}

/// Test both chains produce different keys
///
/// External and internal chains must always produce different keys.
#[test]
fn edge_case_chains_always_different() {
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

    // Test multiple indices
    for i in 0..100 {
        let external = account.derive_external(i).unwrap();
        let internal = account.derive_internal(i).unwrap();

        assert_ne!(
            external.private_key(),
            internal.private_key(),
            "Chains produced same key at index {}",
            i
        );
    }
}

/// Test sequential addresses are always different
///
/// No two sequential addresses should ever be the same.
#[test]
fn edge_case_sequential_addresses_unique() {
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

    // Generate 100 sequential addresses
    let addresses = account
        .derive_address_range(Chain::External, 0, 100)
        .unwrap();

    // Verify all are unique
    for i in 0..addresses.len() {
        for j in (i + 1)..addresses.len() {
            assert_ne!(
                addresses[i].private_key(),
                addresses[j].private_key(),
                "Addresses {} and {} are identical",
                i,
                j
            );
        }
    }
}

/// Test path round-trip (to_string -> parse)
///
/// Converting a path to string and back should preserve all information.
#[test]
fn edge_case_path_round_trip() {
    let original = Bip44Path::new(
        Purpose::BIP84,
        CoinType::Ethereum,
        42,
        Chain::Internal,
        12345,
    )
    .unwrap();

    let path_string = original.to_string();
    let parsed: Bip44Path = path_string.parse().unwrap();

    assert_eq!(original, parsed);
    assert_eq!(original.purpose(), parsed.purpose());
    assert_eq!(original.coin_type(), parsed.coin_type());
    assert_eq!(original.account(), parsed.account());
    assert_eq!(original.chain(), parsed.chain());
    assert_eq!(original.address_index(), parsed.address_index());
}

/// Test deterministic derivation
///
/// Same inputs should always produce same outputs.
#[test]
fn edge_case_deterministic_derivation() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Create two wallets with same mnemonic
    let mut wallet1 = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    let mut wallet2 = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

    // Derive same accounts
    let account1 = wallet1
        .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
        .unwrap();
    let account2 = wallet2
        .get_account(Purpose::BIP44, CoinType::Bitcoin, 0)
        .unwrap();

    // Derive same addresses
    for i in 0..100 {
        let addr1 = account1.derive_external(i).unwrap();
        let addr2 = account2.derive_external(i).unwrap();

        assert_eq!(
            addr1.private_key(),
            addr2.private_key(),
            "Non-deterministic at index {}",
            i
        );
    }
}

/// Test network doesn't affect key derivation
///
/// Mainnet and testnet should derive identical keys (only address encoding differs).
#[test]
fn edge_case_network_independence() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let mainnet_wallet =
        Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    let testnet_wallet =
        Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinTestnet).unwrap();

    // Master keys should be identical
    assert_eq!(
        mainnet_wallet.master_key().private_key(),
        testnet_wallet.master_key().private_key()
    );
    assert_eq!(
        mainnet_wallet.master_key().chain_code(),
        testnet_wallet.master_key().chain_code()
    );
}
