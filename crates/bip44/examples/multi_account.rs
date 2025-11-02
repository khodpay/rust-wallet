//! Multi-account wallet example.
//!
//! This example demonstrates managing multiple accounts for a single cryptocurrency:
//! - Personal, business, and savings accounts
//! - Generating addresses for each account
//! - Batch address generation
//!
//! Run with: cargo run --example multi_account

use khodpay_bip32::Network;
use khodpay_bip44::{Chain, CoinType, Language, Purpose, Wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Multi-Account Wallet Example ===\n");

    // Create a wallet
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let mut wallet =
        Wallet::from_mnemonic(mnemonic, "", Language::English, Network::BitcoinMainnet)?;

    println!("Wallet created for Bitcoin\n");

    // Account 0: Personal
    println!("--- Account 0: Personal ---");
    let (personal_addrs, _personal_change) = {
        let personal = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;
        println!("  Path: m/44'/0'/0'");
        println!("  Purpose: Use for personal transactions");

        // Generate first 3 receiving addresses
        println!("  Receiving addresses:");
        let mut addrs = Vec::new();
        for i in 0..3 {
            let addr = personal.derive_external(i)?;
            println!("    {}: m/44'/0'/0'/0/{} (depth: {})", i, i, addr.depth());
            addrs.push(addr);
        }

        // Generate first 2 change addresses
        println!("  Change addresses:");
        let mut change = Vec::new();
        for i in 0..2 {
            let addr = personal.derive_internal(i)?;
            println!("    {}: m/44'/0'/0'/1/{} (depth: {})", i, i, addr.depth());
            change.push(addr);
        }
        (addrs, change)
    };
    println!();

    // Account 1: Business
    println!("--- Account 1: Business ---");
    let business_addrs = {
        let business = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 1)?;
        println!("  Path: m/44'/0'/1'");
        println!("  Purpose: Use for business transactions");

        // Batch generate addresses
        let addrs = business.derive_address_range(Chain::External, 0, 5)?;
        println!("  Receiving addresses (batch):");
        for (i, addr) in addrs.iter().enumerate() {
            println!("    {}: m/44'/0'/1'/0/{} (depth: {})", i, i, addr.depth());
        }
        addrs
    };
    println!();

    // Account 2: Savings
    println!("--- Account 2: Savings ---");
    let _savings_addr = {
        let savings = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 2)?;
        println!("  Path: m/44'/0'/2'");
        println!("  Purpose: Long-term savings");

        // Generate just the first address
        let addr = savings.derive_external(0)?;
        println!(
            "  Primary address: m/44'/0'/2'/0/0 (depth: {})",
            addr.depth()
        );
        addr
    };
    println!();

    // Account 3: Donations
    println!("--- Account 3: Donations ---");
    let _donation_addr = {
        let donations = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 3)?;
        println!("  Path: m/44'/0'/3'");
        println!("  Purpose: Receive donations");

        let addr = donations.derive_external(0)?;
        println!(
            "  Donation address: m/44'/0'/3'/0/0 (depth: {})",
            addr.depth()
        );
        addr
    };
    println!();

    // Demonstrate account independence
    println!("--- Account Independence ---");
    let personal_addr = &personal_addrs[0];
    let business_addr = &business_addrs[0];

    println!("  Personal address 0 and Business address 0 are different:");
    println!("    Same index, different accounts");
    println!("    Personal: depth {}", personal_addr.depth());
    println!("    Business: depth {}", business_addr.depth());
    println!("    Keys are cryptographically independent");
    println!();

    // Summary
    println!("--- Summary ---");
    println!("  Total accounts: 4 (Personal, Business, Savings, Donations)");
    println!("  Cached accounts: {}", wallet.cached_account_count());
    println!("  All accounts derived from the same seed");
    println!("  Each account has independent address space");
    println!();

    // Use case examples
    println!("--- Use Case Examples ---");
    println!("  Personal (Account 0):");
    println!("    - Daily spending");
    println!("    - Receiving payments from friends");
    println!();
    println!("  Business (Account 1):");
    println!("    - Customer payments");
    println!("    - Business expenses");
    println!("    - Separate accounting");
    println!();
    println!("  Savings (Account 2):");
    println!("    - Long-term holdings");
    println!("    - Minimal transactions");
    println!("    - Cold storage");
    println!();
    println!("  Donations (Account 3):");
    println!("    - Public donation address");
    println!("    - Transparent funding");
    println!();

    println!("=== Example Complete ===");

    Ok(())
}
