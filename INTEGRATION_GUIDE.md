# KhodPay Wallet Libraries - Integration Guide

This guide explains how to integrate the BIP39 and BIP32 libraries into your Rust projects.

## 📦 Available Libraries

### 1. **khodpay-bip39** - Mnemonic Code Generation
- ✅ BIP39-compliant mnemonic generation and validation
- ✅ Support for 12, 15, 18, 21, and 24-word mnemonics
- ✅ Secure seed derivation with PBKDF2-HMAC-SHA512
- ✅ Multiple language support
- ✅ Memory-safe (zeroization of sensitive data)

### 2. **khodpay-bip32** - Hierarchical Deterministic Wallets
- ✅ BIP32-compliant hierarchical key derivation
- ✅ Master key generation from seed
- ✅ Extended private and public keys
- ✅ Fingerprint calculation (HASH160)
- ✅ Memory-safe (zeroization of sensitive data)
- ✅ Full secp256k1 support

## 🚀 Integration Methods

### Method 1: Local Path Dependency (Development)

Add to your project's `Cargo.toml`:

```toml
[dependencies]
khodpay-bip39 = { path = "../khodpay-wallet/crates/bip39" }
khodpay-bip32 = { path = "../khodpay-wallet/crates/bip32" }
```

### Method 2: Git Dependency (Recommended for Projects)

```toml
[dependencies]
khodpay-bip39 = { git = "https://github.com/khodpay/rust-wallet" }
khodpay-bip32 = { git = "https://github.com/khodpay/rust-wallet" }
```

### Method 3: Workspace Dependency (Monorepo)

If your project is in the same workspace:

```toml
[dependencies]
khodpay-bip39 = { workspace = true }
khodpay-bip32 = { workspace = true }
```

## 📖 Usage Examples

### Example 1: Generate Wallet from Mnemonic

```rust
use khodpay_bip39::{Mnemonic, Language};
use khodpay_bip32::{ExtendedPrivateKey, Network};

fn create_wallet() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a 24-word mnemonic
    let mnemonic = Mnemonic::generate(24)?;
    println!("Mnemonic: {}", mnemonic.to_string());
    
    // Derive seed from mnemonic (with optional passphrase)
    let seed = mnemonic.to_seed("optional_passphrase");
    
    // Create master extended private key
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    
    // Get master public key (for watch-only wallet)
    let master_pub = master_key.to_extended_public_key();
    
    println!("Master key depth: {}", master_key.depth());
    println!("Master fingerprint: {:02x?}", master_key.fingerprint());
    
    Ok(())
}
```

### Example 2: Recover Wallet from Mnemonic

```rust
use khodpay_bip39::{Mnemonic, Language};
use khodpay_bip32::{ExtendedPrivateKey, Network};

fn recover_wallet(mnemonic_phrase: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Parse mnemonic from string
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English)?;
    
    // Verify mnemonic is valid
    if !mnemonic.validate() {
        return Err("Invalid mnemonic".into());
    }
    
    // Derive seed
    let seed = mnemonic.to_seed("");
    
    // Restore master key
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    
    println!("Wallet restored successfully!");
    println!("Fingerprint: {:02x?}", master_key.fingerprint());
    
    Ok(())
}
```

### Example 3: Multi-Language Support

```rust
use bip39::{Mnemonic, Language};

fn generate_mnemonic_in_language(lang: Language) -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = Mnemonic::generate_in(12, lang)?;
    
    match lang {
        Language::English => println!("English: {}", mnemonic.to_string()),
        Language::Japanese => println!("日本語: {}", mnemonic.to_string()),
        Language::Korean => println!("한국어: {}", mnemonic.to_string()),
        Language::Spanish => println!("Español: {}", mnemonic.to_string()),
        Language::ChineseSimplified => println!("简体中文: {}", mnemonic.to_string()),
        Language::ChineseTraditional => println!("繁體中文: {}", mnemonic.to_string()),
        Language::French => println!("Français: {}", mnemonic.to_string()),
        Language::Italian => println!("Italiano: {}", mnemonic.to_string()),
        Language::Czech => println!("Čeština: {}", mnemonic.to_string()),
        Language::Portuguese => println!("Português: {}", mnemonic.to_string()),
    }
    
    Ok(())
}
```

### Example 4: Watch-Only Wallet

```rust
use khodpay_bip39::Mnemonic;
use khodpay_bip32::{ExtendedPrivateKey, ExtendedPublicKey, Network};

fn create_watch_only_wallet() -> Result<ExtendedPublicKey, Box<dyn std::error::Error>> {
    let mnemonic = Mnemonic::generate(24)?;
    let seed = mnemonic.to_seed("");
    let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    
    // Convert to public key (can be shared safely)
    let master_pub = master_priv.to_extended_public_key();
    
    // The private key can now be securely stored/destroyed
    drop(master_priv); // Automatically zeroized!
    
    // Use public key for watch-only operations
    println!("Watch-only wallet created!");
    println!("Public key fingerprint: {:02x?}", master_pub.fingerprint());
    
    Ok(master_pub)
}
```

## 🔐 Security Features

Both libraries implement security best practices:

### Memory Zeroization
```rust
use khodpay_bip39::Mnemonic;
use khodpay_bip32::ExtendedPrivateKey;

{
    let mnemonic = Mnemonic::generate(24)?;
    let seed = mnemonic.to_seed("");
    let key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    
    // Use the key...
    
} // Automatically zeroized on drop! 🔒
```

### Secure Debug Output
```rust
use khodpay_bip32::ExtendedPrivateKey;

let key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;

// Debug output redacts sensitive fields
println!("{:?}", key);
// Output: ExtendedPrivateKey { network: BitcoinMainnet, depth: 0, 
//         chain_code: "[REDACTED]", private_key: "[REDACTED]" }
```

## 🏗️ Build Artifacts

After running `cargo build --release --workspace`, you'll find:

```
target/release/
├── libkhodpay_bip39.rlib      (1.7 MB) - BIP39 library
├── libkhodpay_bip32.rlib      (229 KB) - BIP32 library
└── deps/              - All dependencies
```

## 📋 Feature Status

### BIP39 (Complete)
- ✅ Mnemonic generation (12-24 words)
- ✅ Mnemonic validation
- ✅ Seed derivation (PBKDF2-HMAC-SHA512)
- ✅ 10 language support
- ✅ Entropy validation
- ✅ Memory safety (zeroization)

### BIP32 (In Progress - 24/92 tasks complete)
- ✅ Network definitions (Bitcoin Mainnet/Testnet)
- ✅ Core cryptographic types (PrivateKey, PublicKey, ChainCode)
- ✅ Extended key structures (ExtendedPrivateKey, ExtendedPublicKey)
- ✅ Master key generation from seed
- ✅ Extended public key conversion
- ✅ Fingerprint calculation (HASH160)
- ✅ Memory safety (zeroization)
- 🔲 Derivation path parsing (m/44'/0'/0'/0/0)
- 🔲 Child key derivation (CKD functions)
- 🔲 Hardened/normal derivation
- 🔲 Extended key serialization (xprv/xpub)

## 🧪 Testing

Run tests for both libraries:

```bash
# Test everything
cargo test --workspace

# Test specific library
cargo test -p khodpay-bip39
cargo test -p khodpay-bip32

# Run with output
cargo test --workspace -- --nocapture

# Run specific test
cargo test -p khodpay-bip32 fingerprint
```

Current test status:
- **khodpay-bip39**: All tests passing ✅
- **khodpay-bip32**: 145 unit tests + 50 doc tests passing ✅

## 📚 Documentation

Generate and open documentation:

```bash
# Generate docs for all crates
cargo doc --workspace --no-deps --open

# Generate docs for specific crate
cargo doc -p bip39 --open
cargo doc -p bip32 --open
```

## 🔧 Minimum Requirements

```toml
[package]
edition = "2021"
rust-version = "1.70"  # Minimum Rust version

[dependencies]
bip39 = "0.1.0"
bip32 = "0.1.0"
```

## 📦 Dependencies Overview

### BIP39 Dependencies
- `hmac` - HMAC implementation
- `sha2` - SHA-256/SHA-512 hashing
- `pbkdf2` - Key derivation
- `rand` - Secure random number generation
- `thiserror` - Error handling
- `zeroize` - Memory zeroization

### BIP32 Dependencies
- `secp256k1` - Elliptic curve cryptography
- `hmac` - HMAC-SHA512 for key derivation
- `sha2` - SHA-256 hashing
- `ripemd` - RIPEMD-160 hashing
- `hex` - Hex encoding/decoding
- `thiserror` - Error handling
- `zeroize` - Memory zeroization

## 🐛 Error Handling

Both libraries use custom error types:

```rust
use khodpay_bip39::{Mnemonic, Error as Bip39Error};
use khodpay_bip32::{ExtendedPrivateKey, Error as Bip32Error};

fn wallet_operation() -> Result<(), Box<dyn std::error::Error>> {
    // BIP39 errors
    let mnemonic = Mnemonic::generate(24)
        .map_err(|e: Bip39Error| format!("Mnemonic error: {}", e))?;
    
    // BIP32 errors
    let seed = mnemonic.to_seed("");
    let key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
        .map_err(|e: Bip32Error| format!("Key derivation error: {}", e))?;
    
    Ok(())
}
```

## 🤝 Contributing

See individual crate READMEs for contribution guidelines:
- `/crates/bip39/README.md`
- `/crates/bip32/README.md`

## 📄 License

Check the main project LICENSE file for licensing information.

## 🔗 Resources

- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [Project Repository](https://github.com/your-org/khodpay-wallet)

---

**Built with ❤️ for the Bitcoin ecosystem**
