//! Basic BIP-44 wallet usage example.
//!
//! This example demonstrates the fundamental operations of a BIP-44 wallet:
//! - Creating a wallet from a mnemonic
//! - Deriving a Bitcoin account
//! - Generating receiving and change addresses
//!
//! Run with: cargo run --example basic

use khodpay_bip32::Network;
use khodpay_bip44::{CoinType, Language, Purpose, Wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Basic BIP-44 Wallet Example ===\n");

    // Step 1: Create a wallet from a mnemonic phrase
    // In production, generate this securely or load from secure storage
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    println!("Creating wallet from mnemonic...");
    let mut wallet = Wallet::from_mnemonic(
        mnemonic,
        "", // No password (BIP-39 passphrase)
        Language::English,
        Network::BitcoinMainnet,
    )?;

    println!("✓ Wallet created successfully\n");

    // Step 2: Get the first Bitcoin account (BIP-44)
    println!("Deriving Bitcoin account 0...");
    let account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;

    println!("✓ Account derived");
    println!("  Purpose: BIP-{}", account.purpose().value());
    println!(
        "  Coin: {} ({})",
        account.coin_type().name(),
        account.coin_type().symbol()
    );
    println!("  Account: {}", account.account_index());
    println!("  Network: {:?}\n", account.network());

    // Step 3: Generate receiving addresses (external chain)
    println!("Generating receiving addresses (external chain):");
    for i in 0..5 {
        let address = account.derive_external(i)?;
        let path = format!(
            "m/{}'/{}'/{}'/{}/{}",
            account.purpose().value(),
            account.coin_type().index(),
            account.account_index(),
            0, // External chain
            i
        );
        println!("  Address {}: {} (depth: {})", i, path, address.depth());
    }
    println!();

    // Step 4: Generate change addresses (internal chain)
    println!("Generating change addresses (internal chain):");
    for i in 0..3 {
        let address = account.derive_internal(i)?;
        let path = format!(
            "m/{}'/{}'/{}'/{}/{}",
            account.purpose().value(),
            account.coin_type().index(),
            account.account_index(),
            1, // Internal chain
            i
        );
        println!("  Change {}: {} (depth: {})", i, path, address.depth());
    }
    println!();

    // Step 5: Show account caching
    println!("Account caching:");
    println!("  Cached accounts: {}", wallet.cached_account_count());

    // Access the same account again (uses cache)
    let _account_cached = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;
    println!("  After re-access: {}", wallet.cached_account_count());
    println!("  ✓ Account was retrieved from cache\n");

    println!("=== Example Complete ===");

    Ok(())
}
