//! Account discovery example using gap limit.
//!
//! This example demonstrates how to discover used addresses in a wallet
//! using the BIP-44 gap limit standard (20 consecutive unused addresses).
//!
//! Run with: cargo run --example discovery

use khodpay_bip32::Network;
use khodpay_bip44::{
    AccountDiscovery, CoinType, GapLimitChecker, Language, Purpose, Wallet, DEFAULT_GAP_LIMIT,
};
use std::collections::HashSet;

/// Mock blockchain for demonstration purposes.
/// In production, this would query a real blockchain API.
struct MockBlockchain {
    used_indices: HashSet<u32>,
}

impl MockBlockchain {
    fn new_external() -> Self {
        let mut used = HashSet::new();

        // Simulate that these addresses have been used
        // In reality, you'd check the blockchain
        used.insert(0);
        used.insert(1);
        used.insert(5);
        used.insert(10);

        Self { used_indices: used }
    }

    fn new_internal() -> Self {
        let mut used = HashSet::new();

        // Change addresses
        used.insert(0);
        used.insert(2);

        Self { used_indices: used }
    }

    fn format_path(purpose: u32, coin: u32, account: u32, chain: u32, index: u32) -> String {
        format!("m/{}'/{}'/{}'/{}/{}", purpose, coin, account, chain, index)
    }
}

impl AccountDiscovery for MockBlockchain {
    fn is_address_used(&self, address_index: u32) -> Result<bool, Box<dyn std::error::Error>> {
        // In production, query blockchain API here
        Ok(self.used_indices.contains(&address_index))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Account Discovery Example ===\n");

    // Create a wallet
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let mut wallet =
        Wallet::from_mnemonic(mnemonic, "", Language::English, Network::BitcoinMainnet)?;

    println!("Wallet created from mnemonic");
    println!("Gap limit: {} addresses\n", DEFAULT_GAP_LIMIT);

    // Get the first Bitcoin account
    let _account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;

    // Create mock blockchains
    let external_blockchain = MockBlockchain::new_external();

    println!("Simulated used external addresses:");
    for &index in &external_blockchain.used_indices {
        let path = MockBlockchain::format_path(44, 0, 0, 0, index);
        println!("  ✓ {}", path);
    }
    println!();

    // Create gap limit checker
    let checker = GapLimitChecker::new(DEFAULT_GAP_LIMIT);

    // Scan external chain (receiving addresses)
    println!("--- Scanning External Chain (Receiving) ---");
    println!(
        "Checking addresses with gap limit of {}...\n",
        DEFAULT_GAP_LIMIT
    );

    let external_last = checker.find_last_used_index(&external_blockchain, 0)?;

    println!("External chain results:");
    println!("  Last used index: {:?}", external_last);

    if let Some(last_used) = external_last {
        println!("  Used address indices:");
        for i in 0..=last_used {
            if external_blockchain.is_address_used(i)? {
                let path = MockBlockchain::format_path(44, 0, 0, 0, i);
                println!("    ✓ Index {}: {}", i, path);
            }
        }
        println!("  Total used: {}", external_blockchain.used_indices.len());
    } else {
        println!("  No used addresses found");
    }
    println!();

    // Scan internal chain (change addresses)
    println!("--- Scanning Internal Chain (Change) ---");
    println!(
        "Checking addresses with gap limit of {}...\n",
        DEFAULT_GAP_LIMIT
    );

    // Create a new mock blockchain for internal chain
    let internal_blockchain = MockBlockchain::new_internal();

    let internal_last = checker.find_last_used_index(&internal_blockchain, 0)?;

    println!("Internal chain results:");
    println!("  Last used index: {:?}", internal_last);

    if let Some(last_used) = internal_last {
        println!("  Used address indices:");
        for i in 0..=last_used {
            if internal_blockchain.is_address_used(i)? {
                let path = MockBlockchain::format_path(44, 0, 0, 1, i);
                println!("    ✓ Index {}: {}", i, path);
            }
        }
        println!("  Total used: {}", internal_blockchain.used_indices.len());
    } else {
        println!("  No used addresses found");
    }
    println!();

    // Summary
    println!("--- Discovery Summary ---");
    let total_used =
        external_blockchain.used_indices.len() + internal_blockchain.used_indices.len();

    println!("  Total used addresses: {}", total_used);
    println!(
        "  External used: {}",
        external_blockchain.used_indices.len()
    );
    println!(
        "  Internal used: {}",
        internal_blockchain.used_indices.len()
    );
    println!();

    // Explain gap limit
    println!("--- Gap Limit Explanation ---");
    println!("  The gap limit is a BIP-44 standard that defines when to stop");
    println!("  scanning for used addresses during wallet recovery.");
    println!();
    println!("  How it works:");
    println!("    1. Start scanning from address index 0");
    println!("    2. Check each address for transactions on the blockchain");
    println!("    3. Count consecutive unused addresses");
    println!(
        "    4. Stop when {} consecutive unused addresses are found",
        DEFAULT_GAP_LIMIT
    );
    println!();
    println!("  Why it matters:");
    println!("    - Ensures all used addresses are discovered");
    println!("    - Prevents infinite scanning");
    println!("    - Standard across all BIP-44 wallets");
    println!();

    // Practical example
    println!("--- Practical Usage ---");
    println!("  In a real application:");
    println!("    1. Implement AccountDiscovery trait for your blockchain client");
    println!("    2. Query blockchain API to check for transactions");
    println!("    3. Use GapLimitChecker to scan accounts");
    println!("    4. Restore wallet state from discovered addresses");
    println!();
    println!("  Example blockchain APIs:");
    println!("    - Bitcoin: Blockstream, Blockchain.info, Electrum");
    println!("    - Ethereum: Etherscan, Infura, Alchemy");
    println!("    - Multi-coin: BlockCypher, Tatum");
    println!();

    println!("=== Example Complete ===");

    Ok(())
}
