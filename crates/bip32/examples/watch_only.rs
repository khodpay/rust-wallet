//! Example demonstrating watch-only wallet creation and public key derivation.
//!
//! This example shows:
//! - Creating a watch-only wallet using extended public keys
//! - Deriving receive and change addresses without private keys
//! - Security model of public key derivation
//! - Use cases for watch-only wallets
//!
//! Run this example with:
//! ```bash
//! cargo run -p bip32 --example watch_only
//! ```

use bip32::{ChildNumber, DerivationPath, ExtendedPrivateKey, Network};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("👁️  BIP32 Watch-Only Wallet Example\n");
    println!("{}", "=".repeat(70));

    // ========================================================================
    // STEP 1: Setup - Create Master Key (Hot Wallet / Secure Environment)
    // ========================================================================
    println!("\n🔐 STEP 1: Creating Master Key (in secure environment)");
    println!("{}", "-".repeat(70));
    println!("This step happens on a secure device with private key access");
    println!();

    let seed = b"secure-seed-stored-on-hardware-wallet-or-secure-enclave!!";
    let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet)?;

    println!("✅ Master key created");
    println!("   Fingerprint: {}", hex::encode(master.fingerprint()));

    // ========================================================================
    // STEP 2: Derive Account Key (Still in Secure Environment)
    // ========================================================================
    println!("\n🔑 STEP 2: Deriving Account Key (m/44'/0'/0')");
    println!("{}", "-".repeat(70));
    println!("Using hardened derivation for security");
    println!();

    // BIP-44 path: m/44'/0'/0' (purpose/coin_type/account)
    let account_path = DerivationPath::from_str("m/44'/0'/0'")?;
    let account_key = master.derive_path(&account_path)?;

    println!("✅ Account key derived");
    println!("   Path: m/44'/0'/0'");
    println!("   Depth: {}", account_key.depth());

    // ========================================================================
    // STEP 3: Export Public Key (Transfer to Watch-Only Environment)
    // ========================================================================
    println!("\n🌐 STEP 3: Exporting Extended Public Key");
    println!("{}", "-".repeat(70));
    println!("This xpub can be safely shared with watch-only wallets");
    println!();

    let account_xpub = account_key.to_extended_public_key();
    let xpub_string = account_xpub.to_string();

    println!("✅ Extended Public Key (xpub):");
    println!("   {}", xpub_string);
    println!("\n⚠️  SECURITY NOTE:");
    println!("   - This xpub can generate all receive/change addresses");
    println!("   - Share only with trusted watch-only systems");
    println!("   - Cannot derive hardened children (account-level keys)");
    println!("   - Cannot sign transactions or spend funds");

    // ========================================================================
    // STEP 4: Watch-Only Wallet - Derive Receiving Addresses
    // ========================================================================
    println!("\n\n👁️  STEP 4: Watch-Only Wallet - Generating Receiving Addresses");
    println!("{}", "=".repeat(70));
    println!("Now operating in watch-only mode (no private keys)");
    println!();

    // Parse the xpub (simulating loading it in a watch-only wallet)
    let watch_only_account = bip32::ExtendedPublicKey::from_str(&xpub_string)?;

    println!("✅ Loaded xpub into watch-only wallet");
    println!("   Network: {:?}", watch_only_account.network());
    println!("   Depth: {}", watch_only_account.depth());
    println!();

    // Derive external chain (receiving addresses)
    println!("📬 Deriving Receiving Addresses (external chain, index 0):");
    println!("{}", "-".repeat(70));

    let receive_chain = watch_only_account.derive_child(ChildNumber::Normal(0))?;
    println!("✅ Receive chain: m/44'/0'/0'/0");
    println!();

    // Generate first 5 receiving addresses
    for i in 0..5 {
        let address_key = receive_chain.derive_child(ChildNumber::Normal(i))?;
        println!("   Address {}: m/44'/0'/0'/0/{}", i, i);
        println!("   xpub: {}", address_key);
        println!();
    }

    // ========================================================================
    // STEP 5: Watch-Only Wallet - Derive Change Addresses
    // ========================================================================
    println!("\n💰 STEP 5: Deriving Change Addresses (internal chain, index 1)");
    println!("{}", "-".repeat(70));

    let change_chain = watch_only_account.derive_child(ChildNumber::Normal(1))?;
    println!("✅ Change chain: m/44'/0'/0'/1");
    println!();

    // Generate first 3 change addresses
    for i in 0..3 {
        let change_key = change_chain.derive_child(ChildNumber::Normal(i))?;
        println!("   Change {}: m/44'/0'/0'/1/{}", i, i);
        println!("   xpub: {}", change_key);
        println!();
    }

    // ========================================================================
    // STEP 6: Use Cases for Watch-Only Wallets
    // ========================================================================
    println!("\n📊 STEP 6: Watch-Only Wallet Use Cases");
    println!("{}", "=".repeat(70));

    println!("\n✅ E-commerce / Point of Sale:");
    println!("   - Generate unique addresses for each customer");
    println!("   - Monitor incoming payments without private keys");
    println!("   - Reduce security risk on public-facing systems");

    println!("\n✅ Accounting / Portfolio Tracking:");
    println!("   - View all transactions and balances");
    println!("   - Generate reports without spending capability");
    println!("   - Share with accountants safely");

    println!("\n✅ Multi-signature Coordinator:");
    println!("   - Coordinate between multiple signers");
    println!("   - Generate addresses without full spending authority");
    println!("   - Monitor multisig wallet activity");

    println!("\n✅ Cold Storage Monitoring:");
    println!("   - Monitor cold wallet balances");
    println!("   - Generate deposit addresses");
    println!("   - Keep private keys offline");

    // ========================================================================
    // STEP 7: Security Model
    // ========================================================================
    println!("\n\n🔒 STEP 7: Security Model");
    println!("{}", "=".repeat(70));

    println!("\n✅ What Watch-Only Wallets CAN do:");
    println!("   ✓ Derive receive addresses (m/44'/0'/0'/0/i)");
    println!("   ✓ Derive change addresses (m/44'/0'/0'/1/i)");
    println!("   ✓ View all transactions");
    println!("   ✓ Check balances");
    println!("   ✓ Generate QR codes for receiving");

    println!("\n❌ What Watch-Only Wallets CANNOT do:");
    println!("   ✗ Sign transactions");
    println!("   ✗ Spend funds");
    println!("   ✗ Derive hardened children (account-level keys)");
    println!("   ✗ Access private keys");
    println!("   ✗ Recover parent private key");

    println!("\n⚠️  IMPORTANT SECURITY NOTES:");
    println!("   - xpub reveals all public keys in the branch");
    println!("   - If xpub + any child private key leaked, parent private key at risk");
    println!("   - Always use hardened derivation for account level (m/44'/0'/0')");
    println!("   - Only share xpub with systems you trust");

    // ========================================================================
    // STEP 8: Comparison with Private Key Derivation
    // ========================================================================
    println!("\n\n🔀 STEP 8: Verification - Public vs Private Derivation");
    println!("{}", "=".repeat(70));
    println!("Demonstrating that public key derivation matches private key derivation");
    println!();

    // Derive from private key
    let receive_from_private = account_key
        .derive_child(ChildNumber::Normal(0))?
        .derive_child(ChildNumber::Normal(0))?;

    // Derive from public key
    let receive_from_public = watch_only_account
        .derive_child(ChildNumber::Normal(0))?
        .derive_child(ChildNumber::Normal(0))?;

    println!("✅ Address 0 derived from private key:");
    println!("   {}", receive_from_private.to_extended_public_key());
    println!();
    println!("✅ Address 0 derived from public key (watch-only):");
    println!("   {}", receive_from_public);
    println!();

    let keys_match = receive_from_private.to_extended_public_key().to_string() 
        == receive_from_public.to_string();
    println!("🎯 Keys match: {}", keys_match);

    if keys_match {
        println!("\n✅ SUCCESS! Public key derivation produces identical results");
        println!("   This enables watch-only wallets while maintaining security.");
    }

    // ========================================================================
    // STEP 9: Best Practices
    // ========================================================================
    println!("\n\n💡 STEP 9: Best Practices for Watch-Only Wallets");
    println!("{}", "=".repeat(70));

    println!("\n1️⃣  Account Segregation:");
    println!("   - Use separate accounts for different purposes");
    println!("   - m/44'/0'/0' for personal, m/44'/0'/1' for business");
    println!("   - Each account has its own xpub");

    println!("\n2️⃣  xpub Storage:");
    println!("   - Store xpub securely (not plaintext in databases)");
    println!("   - Use encryption for xpub storage");
    println!("   - Rotate xpub if potentially compromised");

    println!("\n3️⃣  Address Reuse:");
    println!("   - Never reuse addresses");
    println!("   - Generate new address for each transaction");
    println!("   - Use gap limit (typically 20) for address discovery");

    println!("\n4️⃣  Private Key Management:");
    println!("   - Keep private keys on hardware wallets");
    println!("   - Use hardened derivation for all account-level keys");
    println!("   - Never expose private keys to watch-only systems");

    println!("\n5️⃣  Monitoring:");
    println!("   - Implement address monitoring");
    println!("   - Track both receive and change addresses");
    println!("   - Set up alerts for incoming transactions");

    // ========================================================================
    // Summary
    // ========================================================================
    println!("\n\n📋 Summary");
    println!("{}", "=".repeat(70));
    println!("✅ Created master key in secure environment");
    println!("✅ Derived account key with hardened derivation");
    println!("✅ Exported extended public key (xpub)");
    println!("✅ Generated receiving addresses in watch-only mode");
    println!("✅ Generated change addresses in watch-only mode");
    println!("✅ Verified public derivation matches private derivation");
    println!("✅ Reviewed security model and use cases");
    println!();
    println!("🎯 Key Takeaway: Watch-only wallets enable secure address generation");
    println!("   and balance monitoring without exposing private keys to online systems.");

    Ok(())
}
