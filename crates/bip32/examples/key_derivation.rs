//! Example demonstrating various key derivation patterns and paths.
//!
//! This example shows:
//! - BIP-44 standard path derivation
//! - BIP-49 SegWit path derivation
//! - BIP-84 Native SegWit path derivation
//! - Custom derivation paths
//! - Hardened vs normal derivation
//!
//! Run this example with:
//! ```bash
//! cargo run -p bip32 --example key_derivation
//! ```

use bip32::{ChildNumber, DerivationPath, ExtendedPrivateKey, Network};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔑 BIP32 Key Derivation Examples\n");
    println!("{}", "=".repeat(70));

    // Create a master key from a test seed
    let seed = b"super-secret-seed-for-testing-only-do-not-use-in-production!!";
    let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet)?;

    println!("\n📊 Master Key Information:");
    println!("{}", "-".repeat(70));
    println!("Master xprv: {}", master);
    println!("Master xpub: {}", master.to_extended_public_key());
    println!("Fingerprint: {}", hex::encode(master.fingerprint()));

    // ========================================================================
    // Example 1: BIP-44 Standard Path (m/44'/0'/0')
    // ========================================================================
    println!("\n\n🎯 Example 1: BIP-44 Multi-Account Hierarchy");
    println!("{}", "=".repeat(70));
    println!("Standard: m / purpose' / coin_type' / account' / change / address_index");
    println!("Path:     m / 44'     / 0'        / 0'      / 0      / 0");
    println!("{}", "-".repeat(70));

    let bip44_account = DerivationPath::from_str("m/44'/0'/0'")?;
    let account_key = master.derive_path(&bip44_account)?;

    println!("✅ Account Key (m/44'/0'/0'):");
    println!("   Depth: {}", account_key.depth());
    println!("   xprv: {}", account_key);
    println!("   xpub: {}", account_key.to_extended_public_key());

    // Derive first 3 receiving addresses
    println!("\n📬 Receiving Addresses (m/44'/0'/0'/0/i):");
    for i in 0..3 {
        let address_path = DerivationPath::from_str(&format!("m/44'/0'/0'/0/{}", i))?;
        let address_key = master.derive_path(&address_path)?;
        println!("   Address {}: {}", i, address_key.to_extended_public_key());
    }

    // Derive first 3 change addresses
    println!("\n💰 Change Addresses (m/44'/0'/0'/1/i):");
    for i in 0..3 {
        let change_path = DerivationPath::from_str(&format!("m/44'/0'/0'/1/{}", i))?;
        let change_key = master.derive_path(&change_path)?;
        println!("   Change {}: {}", i, change_key.to_extended_public_key());
    }

    // ========================================================================
    // Example 2: BIP-49 SegWit Path (m/49'/0'/0')
    // ========================================================================
    println!("\n\n🎯 Example 2: BIP-49 SegWit (P2WPKH-nested-in-P2SH)");
    println!("{}", "=".repeat(70));
    println!("Purpose: 49' for SegWit wrapped in P2SH");
    println!("Path:    m/49'/0'/0'/0/0");
    println!("{}", "-".repeat(70));

    let bip49_path = DerivationPath::from_str("m/49'/0'/0'/0/0")?;
    let bip49_key = master.derive_path(&bip49_path)?;

    println!("✅ BIP-49 Address Key:");
    println!("   xpub: {}", bip49_key.to_extended_public_key());
    println!("   Use: P2WPKH-nested-in-P2SH (3... addresses)");

    // ========================================================================
    // Example 3: BIP-84 Native SegWit Path (m/84'/0'/0')
    // ========================================================================
    println!("\n\n🎯 Example 3: BIP-84 Native SegWit (P2WPKH)");
    println!("{}", "=".repeat(70));
    println!("Purpose: 84' for Native SegWit");
    println!("Path:    m/84'/0'/0'/0/0");
    println!("{}", "-".repeat(70));

    let bip84_path = DerivationPath::from_str("m/84'/0'/0'/0/0")?;
    let bip84_key = master.derive_path(&bip84_path)?;

    println!("✅ BIP-84 Address Key:");
    println!("   xpub: {}", bip84_key.to_extended_public_key());
    println!("   Use: Native SegWit (bc1... addresses)");

    // ========================================================================
    // Example 4: Incremental Derivation
    // ========================================================================
    println!("\n\n🎯 Example 4: Incremental Derivation");
    println!("{}", "=".repeat(70));
    println!("Building path step by step instead of all at once");
    println!("{}", "-".repeat(70));

    let mut current_key = master.clone();
    let path_components = [
        (ChildNumber::Hardened(44), "m/44'"),
        (ChildNumber::Hardened(0), "m/44'/0'"),
        (ChildNumber::Hardened(0), "m/44'/0'/0'"),
        (ChildNumber::Normal(0), "m/44'/0'/0'/0"),
        (ChildNumber::Normal(0), "m/44'/0'/0'/0/0"),
    ];

    for (child_num, path_str) in path_components.iter() {
        current_key = current_key.derive_child(*child_num)?;
        println!("✅ {}: depth={}", path_str, current_key.depth());
    }

    println!("\n   Final xpub: {}", current_key.to_extended_public_key());

    // ========================================================================
    // Example 5: Custom Derivation Paths
    // ========================================================================
    println!("\n\n🎯 Example 5: Custom Derivation Paths");
    println!("{}", "=".repeat(70));
    println!("You can create any valid BIP32 path");
    println!("{}", "-".repeat(70));

    let custom_paths = vec![
        "m/0",         // First normal child
        "m/0'",        // First hardened child
        "m/1/2/3/4/5", // Deep normal path
        "m/0'/1/2'/3", // Mixed hardened and normal
    ];

    for path_str in custom_paths {
        let path = DerivationPath::from_str(path_str)?;
        let key = master.derive_path(&path)?;
        println!(
            "✅ Path: {:<20} | Depth: {} | Hardened: {}",
            path_str,
            key.depth(),
            path.contains_hardened()
        );
    }

    // ========================================================================
    // Example 6: Multiple Accounts
    // ========================================================================
    println!("\n\n🎯 Example 6: Multiple Accounts (BIP-44)");
    println!("{}", "=".repeat(70));
    println!("Creating separate accounts for different purposes");
    println!("{}", "-".repeat(70));

    let accounts = vec![("Personal", 0), ("Business", 1), ("Savings", 2)];

    for (name, account_idx) in accounts {
        let account_path = DerivationPath::from_str(&format!("m/44'/0'/{}'", account_idx))?;
        let account_key = master.derive_path(&account_path)?;
        println!("✅ {} Account (m/44'/0'/{}')", name, account_idx);
        println!(
            "   xpub: {}...",
            &account_key.to_extended_public_key().to_string()[..20]
        );
    }

    // ========================================================================
    // Example 7: Hardened vs Normal Derivation
    // ========================================================================
    println!("\n\n🎯 Example 7: Hardened vs Normal Derivation Security");
    println!("{}", "=".repeat(70));
    println!("Demonstrating the difference between hardened and normal derivation");
    println!("{}", "-".repeat(70));

    // Normal derivation - can derive public keys from parent public key
    let normal_parent = master.derive_child(ChildNumber::Normal(0))?;
    let normal_parent_pub = normal_parent.to_extended_public_key();
    let normal_child_from_private = normal_parent.derive_child(ChildNumber::Normal(0))?;
    let normal_child_from_public = normal_parent_pub.derive_child(ChildNumber::Normal(0))?;

    println!("✅ Normal Derivation (m/0/0):");
    println!(
        "   Child from private: {}",
        normal_child_from_private.to_extended_public_key()
    );
    println!("   Child from public:  {}", normal_child_from_public);
    println!(
        "   Match: {}",
        normal_child_from_private
            .to_extended_public_key()
            .to_string()
            == normal_child_from_public.to_string()
    );

    // Hardened derivation - requires private key
    let hardened_parent = master.derive_child(ChildNumber::Hardened(0))?;
    let hardened_child = hardened_parent.derive_child(ChildNumber::Normal(0))?;

    println!("\n✅ Hardened Derivation (m/0'/0):");
    println!("   Requires private key - more secure");
    println!("   Cannot derive children from parent public key alone");
    println!("   Child xpub: {}", hardened_child.to_extended_public_key());

    // ========================================================================
    // Summary
    // ========================================================================
    println!("\n\n📋 Summary");
    println!("{}", "=".repeat(70));
    println!("✅ Demonstrated BIP-44 standard paths");
    println!("✅ Demonstrated BIP-49 SegWit paths");
    println!("✅ Demonstrated BIP-84 Native SegWit paths");
    println!("✅ Showed incremental derivation");
    println!("✅ Created custom derivation paths");
    println!("✅ Derived multiple accounts");
    println!("✅ Compared hardened vs normal derivation");
    println!("\n💡 Key Takeaway: Use hardened derivation (') for upper levels,");
    println!("   normal derivation for address generation to enable watch-only wallets.");

    Ok(())
}
