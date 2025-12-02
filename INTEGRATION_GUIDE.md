# KhodPay Wallet Libraries - Integration Guide

This guide explains how to integrate the KhodPay wallet libraries into your Rust projects.

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

### 3. **khodpay-bip44** - Multi-Account Hierarchy
- ✅ BIP44/49/84/86 compliant account derivation
- ✅ Multi-coin support (Bitcoin, Ethereum, etc.)
- ✅ Account caching for performance
- ✅ External/internal chain derivation

### 4. **khodpay-signing** - EVM Transaction Signing
- ✅ EIP-1559 (Type 2) transaction support
- ✅ BSC Mainnet (56) and Testnet (97) chain IDs
- ✅ BIP-44 integration for key derivation
- ✅ RLP encoding for transaction broadcast
- ✅ Signature recovery for address verification
- ✅ Automatic zeroization of sensitive data

## 🚀 Integration Methods

### Method 1: Local Path Dependency (Development)

Add to your project's `Cargo.toml`:

```toml
[dependencies]
khodpay-bip39 = { path = "../khodpay-wallet/crates/bip39" }
khodpay-bip32 = { path = "../khodpay-wallet/crates/bip32" }
khodpay-bip44 = { path = "../khodpay-wallet/crates/bip44" }
khodpay-signing = { path = "../khodpay-wallet/crates/khodpay-signing" }
```

### Method 2: Git Dependency (Recommended for Projects)

```toml
[dependencies]
khodpay-bip39 = { git = "https://github.com/khodpay/rust-wallet" }
khodpay-bip32 = { git = "https://github.com/khodpay/rust-wallet" }
khodpay-bip44 = { git = "https://github.com/khodpay/rust-wallet" }
khodpay-signing = { git = "https://github.com/khodpay/rust-wallet" }
```

### Method 3: Workspace Dependency (Monorepo)

If your project is in the same workspace:

```toml
[dependencies]
khodpay-bip39 = { workspace = true }
khodpay-bip32 = { workspace = true }
khodpay-bip44 = { workspace = true }
khodpay-signing = { workspace = true }
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

### Example 5: Sign BSC Transaction

```rust
use khodpay_bip32::Network;
use khodpay_bip44::{CoinType, Purpose, Wallet};
use khodpay_signing::{
    Address, Bip44Signer, ChainId, Eip1559Transaction,
    SignedTransaction, Wei, TRANSFER_GAS,
};

fn sign_bsc_transaction() -> Result<(), Box<dyn std::error::Error>> {
    // Create wallet from mnemonic
    let mut wallet = Wallet::from_english_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
        Network::BitcoinMainnet,
    )?;
    
    // Get Ethereum account (CoinType 60 for EVM chains)
    let account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0)?;
    
    // Create signer from first address
    let signer = Bip44Signer::new(&account, 0)?;
    println!("Sender address: {}", signer.address());
    
    // Build EIP-1559 transaction
    let recipient: Address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".parse()?;
    
    let tx = Eip1559Transaction::builder()
        .chain_id(ChainId::BscMainnet)  // BSC Mainnet = 56
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))  // Tip
        .max_fee_per_gas(Wei::from_gwei(5))           // Max total fee
        .gas_limit(TRANSFER_GAS)                       // 21,000 for transfers
        .to(recipient)
        .value(Wei::from_ether(1))
        .build()?;
    
    // Sign the transaction
    let signature = signer.sign_transaction(&tx)?;
    let signed_tx = SignedTransaction::new(tx, signature);
    
    // Get raw transaction for eth_sendRawTransaction
    let raw_tx = signed_tx.to_raw_transaction();
    println!("Raw TX: {}", raw_tx);
    
    // Get transaction hash
    let tx_hash = signed_tx.tx_hash_hex();
    println!("TX Hash: {}", tx_hash);
    
    Ok(())
}
```

### Example 6: BSC Testnet Transaction

```rust
use khodpay_signing::{ChainId, Eip1559Transaction, Wei, TRANSFER_GAS};

fn build_testnet_transaction() -> Result<Eip1559Transaction, Box<dyn std::error::Error>> {
    let tx = Eip1559Transaction::builder()
        .chain_id(ChainId::BscTestnet)  // BSC Testnet = 97
        .nonce(0)
        .max_priority_fee_per_gas(Wei::from_gwei(1))
        .max_fee_per_gas(Wei::from_gwei(5))
        .gas_limit(TRANSFER_GAS)
        .value(Wei::ZERO)
        .build()?;
    
    Ok(tx)
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
cargo test -p khodpay-bip44
cargo test -p khodpay-signing

# Run with output
cargo test --workspace -- --nocapture

# Run specific test
cargo test -p khodpay-bip32 fingerprint
```

Current test status:
- **khodpay-bip39**: All tests passing ✅
- **khodpay-bip32**: 145 unit tests + 50 doc tests passing ✅
- **khodpay-bip44**: 400+ tests passing ✅
- **khodpay-signing**: 187 tests passing ✅

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

### Signing Dependencies
- `k256` - secp256k1 ECDSA signing
- `sha3` - Keccak-256 hashing
- `rlp` - RLP encoding for transactions
- `primitive-types` - U256 for Wei amounts
- `hex` - Hex encoding/decoding
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
- [BIP44 Specification](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [EIP-1559 Specification](https://eips.ethereum.org/EIPS/eip-1559)
- [EIP-2718 Typed Transactions](https://eips.ethereum.org/EIPS/eip-2718)
- [Project Repository](https://github.com/khodpay/rust-wallet)

---

**Built with ❤️ for the cryptocurrency ecosystem**
