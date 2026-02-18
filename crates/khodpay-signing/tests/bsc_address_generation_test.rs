//! Test demonstrating correct BSC address generation for mainnet and testnet.
//!
//! This test proves that:
//! 1. BSC mainnet and testnet use the SAME EVM addresses
//! 2. The Network parameter (BitcoinMainnet/BitcoinTestnet) does NOT affect address generation
//! 3. Only ChainId differs between BSC mainnet (56) and testnet (97)

use khodpay_bip32::Network;
use khodpay_bip44::{CoinType, Purpose, Wallet};
use khodpay_signing::{Bip44Signer, ChainId, Eip1559Transaction, Wei, TRANSFER_GAS};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn test_bsc_address_same_for_mainnet_and_testnet_network() {
    // Create wallet with BitcoinMainnet
    let mut wallet_mainnet =
        Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();

    // Create wallet with BitcoinTestnet
    let mut wallet_testnet =
        Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinTestnet).unwrap();

    // Get Ethereum accounts (CoinType 60 is used for all EVM chains including BSC)
    let account_mainnet = wallet_mainnet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();

    let account_testnet = wallet_testnet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();

    // Create signers
    let signer_mainnet = Bip44Signer::new(account_mainnet, 0).unwrap();
    let signer_testnet = Bip44Signer::new(account_testnet, 0).unwrap();

    // Get addresses
    let address_mainnet = signer_mainnet.address();
    let address_testnet = signer_testnet.address();

    // CRITICAL: The addresses should be IDENTICAL
    // The Network parameter does NOT affect EVM address generation
    assert_eq!(
        address_mainnet, address_testnet,
        "BSC addresses should be the same regardless of Network parameter"
    );

    println!("\n=== BSC Address Generation Test ===");
    println!("Wallet Network (mainnet): {:?}", Network::BitcoinMainnet);
    println!("Wallet Network (testnet): {:?}", Network::BitcoinTestnet);
    println!("BSC Address (both): {}", address_mainnet);
    println!("\nConclusion: Network parameter does NOT affect EVM addresses!");
}

#[test]
fn test_bsc_mainnet_vs_testnet_correct_usage() {
    // For BSC, ALWAYS use BitcoinMainnet as the Network parameter
    // The Network parameter is irrelevant for EVM chains
    let mut wallet =
        Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();

    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();

    let signer = Bip44Signer::new(account, 0).unwrap();
    let address = signer.address();

    // The SAME address is used for both BSC mainnet and testnet
    println!("\n=== Correct BSC Usage ===");
    println!("Address: {}", address);
    println!("This address works on BOTH BSC mainnet and testnet");

    // For transactions, use ChainId to distinguish mainnet vs testnet
    let tx_mainnet = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet) // Chain ID 56
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build()
        .unwrap();

    let tx_testnet = Eip1559Transaction::builder()
        .chain_id(ChainId::BscTestnet) // Chain ID 97
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .build()
        .unwrap();

    // Sign both transactions with the same signer
    let _sig_mainnet = signer.sign_transaction(&tx_mainnet).unwrap();
    let _sig_testnet = signer.sign_transaction(&tx_testnet).unwrap();

    // Signatures are different because ChainId is part of the signing hash
    assert_ne!(
        tx_mainnet.signing_hash(),
        tx_testnet.signing_hash(),
        "Different ChainIds produce different signing hashes"
    );

    println!("\nTransaction signing:");
    println!("  BSC Mainnet (ChainId 56): signature created");
    println!("  BSC Testnet (ChainId 97): signature created");
    println!("\nUse ChainId to distinguish mainnet vs testnet, NOT Network!");
}

#[test]
fn test_known_bsc_address() {
    // Known test vector: first Ethereum address from standard test mnemonic
    let mut wallet =
        Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();

    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();

    let signer = Bip44Signer::new(account, 0).unwrap();
    let address = signer.address();

    // This is the known first Ethereum/BSC address for path m/44'/60'/0'/0/0
    let expected = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

    assert_eq!(
        address.to_checksum_string().to_lowercase(),
        expected.to_lowercase(),
        "Address should match known test vector"
    );

    println!("\n=== Known Test Vector ===");
    println!("Mnemonic: {}", TEST_MNEMONIC);
    println!("Path: m/44'/60'/0'/0/0");
    println!("Expected: {}", expected);
    println!("Got:      {}", address);
    println!("✓ Address matches known test vector");
}

#[test]
fn test_multiple_bsc_addresses() {
    let mut wallet =
        Wallet::from_english_mnemonic(TEST_MNEMONIC, "", Network::BitcoinMainnet).unwrap();

    let account = wallet
        .get_account(Purpose::BIP44, CoinType::Ethereum, 0)
        .unwrap();

    // Derive multiple addresses
    let addresses: Vec<_> = (0..5)
        .map(|i| {
            let signer = Bip44Signer::new(account, i).unwrap();
            signer.address()
        })
        .collect();

    println!("\n=== Multiple BSC Addresses ===");
    for (i, addr) in addresses.iter().enumerate() {
        println!("Address {}: {}", i, addr);
    }

    // All addresses should be different
    for i in 0..addresses.len() {
        for j in (i + 1)..addresses.len() {
            assert_ne!(
                addresses[i], addresses[j],
                "Addresses {} and {} should be different",
                i, j
            );
        }
    }

    println!("\n✓ All {} addresses are unique", addresses.len());
}

#[test]
fn test_explanation_of_network_vs_chainid() {
    println!("\n=== Understanding Network vs ChainId ===");
    println!();
    println!("Network (from BIP32):");
    println!("  - Used for Bitcoin-specific features");
    println!("  - Affects extended key serialization (xprv vs tprv)");
    println!("  - Affects Bitcoin address encoding");
    println!("  - IGNORED for EVM address generation");
    println!();
    println!("ChainId (from EIP-155):");
    println!("  - Used for EVM transaction replay protection");
    println!("  - BSC Mainnet: ChainId = 56");
    println!("  - BSC Testnet: ChainId = 97");
    println!("  - Ethereum Mainnet: ChainId = 1");
    println!("  - Polygon: ChainId = 137");
    println!();
    println!("For BSC:");
    println!("  1. Use Network::BitcoinMainnet (Network is irrelevant)");
    println!("  2. Use CoinType::Ethereum (60) for key derivation");
    println!("  3. Use ChainId::BscMainnet (56) or ChainId::BscTestnet (97) for transactions");
    println!();
    println!("The SAME address works on both BSC mainnet and testnet!");
}
