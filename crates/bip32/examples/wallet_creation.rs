//! Complete example of using bip39 and bip32 together to create a hierarchical
//! deterministic wallet.
//!
//! Run this example with:
//! ```bash
//! cargo run -p bip32 --example wallet_creation
//! ```

use bip32::{ExtendedPrivateKey, Network};
use bip39::{Language, Mnemonic, WordCount};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 KhodPay Wallet - Complete Example\n");
    println!("{}", "=".repeat(60));

    // ========================================================================
    // STEP 1: Generate Mnemonic (BIP39)
    // ========================================================================
    println!("\n📝 STEP 1: Generating Mnemonic (BIP39)");
    println!("{}", "-".repeat(60));

    let mnemonic = Mnemonic::generate(WordCount::TwentyFour, Language::English)?;
    println!("✅ Generated 24-word mnemonic:");
    println!("   {}\n", mnemonic.phrase());

    println!("   Word count: {:?}", mnemonic.word_count());
    println!("   Language: {:?}", Language::English);

    // ========================================================================
    // STEP 2: Derive Seed from Mnemonic
    // ========================================================================
    println!("\n🌱 STEP 2: Deriving Seed");
    println!("{}", "-".repeat(60));

    let passphrase = ""; // Optional passphrase for extra security
    let seed = mnemonic.to_seed(passphrase)?;

    println!("✅ Seed derived successfully");
    println!("   Seed length: {} bytes", seed.len());
    println!("   Seed (hex): {}...{}", 
        hex::encode(&seed[..8]), 
        hex::encode(&seed[seed.len()-8..])
    );

    // ========================================================================
    // STEP 3: Generate Master Extended Private Key (BIP32)
    // ========================================================================
    println!("\n🔑 STEP 3: Generating Master Extended Private Key (BIP32)");
    println!("{}", "-".repeat(60));

    let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;

    println!("✅ Master extended private key created");
    println!("   Network: {:?}", master_priv.network());
    println!("   Depth: {} (master key)", master_priv.depth());
    println!("   Child number: {:?}", master_priv.child_number());
    println!("   Parent fingerprint: {:02x?}", master_priv.parent_fingerprint());
    println!("   Fingerprint: {:02x?}", master_priv.fingerprint());

    // ========================================================================
    // STEP 4: Generate Master Extended Public Key
    // ========================================================================
    println!("\n🔓 STEP 4: Generating Master Extended Public Key");
    println!("{}", "-".repeat(60));

    let master_pub = master_priv.to_extended_public_key();

    println!("✅ Master extended public key created");
    println!("   Network: {:?}", master_pub.network());
    println!("   Depth: {}", master_pub.depth());
    println!("   Fingerprint: {:02x?}", master_pub.fingerprint());
    println!("\n💡 This public key can be shared for watch-only wallets!");

    // ========================================================================
    // STEP 5: Demonstrate Security Features
    // ========================================================================
    println!("\n🔒 STEP 5: Security Features");
    println!("{}", "-".repeat(60));

    println!("✅ Memory zeroization:");
    println!("   - Private keys automatically zeroized on drop");
    println!("   - Chain codes zeroized on drop");
    println!("   - Mnemonic entropy zeroized on drop");

    println!("\n✅ Debug output protection:");
    println!("   Private key debug: {:?}", master_priv);
    println!("   (Notice: sensitive fields are [REDACTED])");

    println!("\n✅ Public key debug (not redacted):");
    println!("   Public key debug: {:?}", master_pub);

    // ========================================================================
    // STEP 6: Recovery Example
    // ========================================================================
    println!("\n🔄 STEP 6: Wallet Recovery Demo");
    println!("{}", "-".repeat(60));

    let mnemonic_phrase = mnemonic.phrase().to_string();
    println!("📝 Using mnemonic to recover wallet...");

    let recovered_mnemonic = Mnemonic::from_phrase(&mnemonic_phrase, Language::English)?;
    let recovered_seed = recovered_mnemonic.to_seed(passphrase)?;
    let recovered_key = ExtendedPrivateKey::from_seed(&recovered_seed, Network::BitcoinMainnet)?;

    println!("✅ Wallet recovered successfully!");
    println!("   Original fingerprint:  {:02x?}", master_priv.fingerprint());
    println!("   Recovered fingerprint: {:02x?}", recovered_key.fingerprint());

    if master_priv.fingerprint() == recovered_key.fingerprint() {
        println!("   ✅ Fingerprints match - recovery successful!");
    }

    // ========================================================================
    // Summary
    // ========================================================================
    println!("\n{}", "=".repeat(60));
    println!("✅ WALLET CREATION COMPLETE!");
    println!("{}", "=".repeat(60));
    println!("\n📋 Summary:");
    println!("   - Mnemonic: 24 words (256 bits entropy)");
    println!("   - Seed: 64 bytes");
    println!("   - Master private key: Generated");
    println!("   - Master public key: Generated");
    println!("   - Fingerprint: {:02x?}", master_priv.fingerprint());
    println!("\n⚠️  IMPORTANT: Store your mnemonic safely!");
    println!("   Never share your mnemonic or private keys!\n");

    Ok(())
}
