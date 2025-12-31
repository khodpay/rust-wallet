//! Test to demonstrate correct BSC address generation for both mainnet and testnet.
//!
//! This test shows that:
//! 1. The Network parameter (BitcoinMainnet/BitcoinTestnet) does NOT affect EVM address generation
//! 2. BSC mainnet and testnet use the SAME addresses (derived from the same keys)
//! 3. Only the ChainId differs between BSC mainnet (56) and testnet (97) for transaction signing

use khodpay_bip32::{ExtendedPrivateKey, Network};
use khodpay_bip39::{Language, Mnemonic};
use khodpay_bip44::{Account, CoinType, Purpose, Wallet};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn test_bsc_address_generation_mainnet_vs_testnet() {
    // Create two wallets with different Network parameters
    let wallet_mainnet =
        Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();
    let wallet_testnet =
        Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinTestnet).unwrap();

    // Both wallets should have the same master private key (only network metadata differs)
    assert_eq!(
        wallet_mainnet.master_key().private_key().to_bytes(),
        wallet_testnet.master_key().private_key().to_bytes()
    );

    // The ExtendedPrivateKey Display format is different (xprv vs tprv)
    let mainnet_str = wallet_mainnet.master_key().to_string();
    let testnet_str = wallet_testnet.master_key().to_string();
    assert!(mainnet_str.starts_with("xprv"));
    assert!(testnet_str.starts_with("tprv"));
    assert_ne!(mainnet_str, testnet_str); // Different serialization format

    println!("Mainnet master key: {}", mainnet_str);
    println!("Testnet master key: {}", testnet_str);
}

#[test]
fn test_bsc_address_derivation_correct_approach() {
    // For BSC (both mainnet and testnet), always use BitcoinMainnet as the Network parameter
    // The Network parameter is only relevant for Bitcoin-specific address encoding
    let mut wallet =
        Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();

    // Use CoinType::Ethereum (60) for BSC, as BSC is EVM-compatible
    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();

    // Derive the first external address key
    let address_key = account.derive_external(0).unwrap();

    // The private key bytes are what you use for EVM address generation
    let private_key_bytes = address_key.private_key().to_bytes();

    println!("Private key (hex): {}", hex::encode(private_key_bytes));
    println!(
        "Extended key (xprv format): {}",
        address_key.to_string()
    );

    // NOTE: To get the actual EVM address, you need to use khodpay-signing crate:
    // let signer = Bip44Signer::new(&account, 0).unwrap();
    // let address = signer.address(); // This gives you 0x... EVM address
}

#[test]
fn test_extended_key_is_not_an_address() {
    let mnemonic = Mnemonic::from_phrase(TEST_MNEMONIC, Language::English).unwrap();
    let seed = mnemonic.to_seed("").unwrap();

    // Create master key with mainnet
    let master_mainnet = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    let mainnet_str = master_mainnet.to_string();

    // Create master key with testnet
    let master_testnet = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();
    let testnet_str = master_testnet.to_string();

    // Both are serialized extended keys, NOT addresses
    assert!(mainnet_str.starts_with("xprv")); // Bitcoin mainnet extended private key
    assert!(testnet_str.starts_with("tprv")); // Bitcoin testnet extended private key

    // These are NOT EVM addresses (which start with 0x and are 40 hex chars)
    assert!(!mainnet_str.starts_with("0x"));
    assert!(!testnet_str.starts_with("0x"));

    // The underlying private key is the same
    assert_eq!(
        master_mainnet.private_key().to_bytes(),
        master_testnet.private_key().to_bytes()
    );

    println!("\n=== IMPORTANT ===");
    println!("ExtendedPrivateKey.to_string() returns xprv/tprv format, NOT an EVM address!");
    println!("Mainnet format: {}", mainnet_str);
    println!("Testnet format: {}", testnet_str);
    println!("\nTo get an EVM address, use khodpay-signing::Bip44Signer");
}

#[test]
fn test_network_parameter_explanation() {
    // The Network parameter in BIP32/BIP44 is for Bitcoin-specific features:
    // 1. Extended key serialization format (xprv vs tprv, xpub vs tpub)
    // 2. Bitcoin address encoding (P2PKH, P2SH, Bech32)
    //
    // For EVM chains like BSC:
    // - Network parameter is IGNORED for address generation
    // - Addresses are always derived using Keccak-256 hash
    // - Use ChainId (56 for BSC mainnet, 97 for BSC testnet) for transaction signing

    let seed = [0u8; 64];

    // Both produce the same underlying private key
    let key_mainnet = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    let key_testnet = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinTestnet).unwrap();

    assert_eq!(
        key_mainnet.private_key().to_bytes(),
        key_testnet.private_key().to_bytes()
    );

    // Only the serialization format differs
    assert_ne!(key_mainnet.to_string(), key_testnet.to_string());

    println!("\n=== Network Parameter Usage ===");
    println!("For Bitcoin: Network determines address format (1... vs m/n...)");
    println!("For BSC/EVM: Network is irrelevant, use ChainId instead");
    println!("  - BSC Mainnet: ChainId = 56");
    println!("  - BSC Testnet: ChainId = 97");
}
