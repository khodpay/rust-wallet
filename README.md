# KhodPay Wallet Libraries

[![Crates.io - bip39](https://img.shields.io/crates/v/khodpay-bip39)](https://crates.io/crates/khodpay-bip39)
[![Crates.io - bip32](https://img.shields.io/crates/v/khodpay-bip32)](https://crates.io/crates/khodpay-bip32)
[![Crates.io - bip44](https://img.shields.io/crates/v/khodpay-bip44)](https://crates.io/crates/khodpay-bip44)
[![Documentation](https://docs.rs/khodpay-bip39/badge.svg)](https://docs.rs/khodpay-bip39)
[![Documentation](https://docs.rs/khodpay-bip32/badge.svg)](https://docs.rs/khodpay-bip32)
[![Documentation](https://docs.rs/khodpay-bip44/badge.svg)](https://docs.rs/khodpay-bip44)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Build Status](https://img.shields.io/github/workflow/status/khodpay/rust-wallet/CI)](https://github.com/khodpay/rust-wallet/actions)

A production-ready, type-safe Rust implementation of BIP39, BIP32, and BIP44 standards for cryptocurrency wallet development.

## 🚀 Features

### BIP39 - Mnemonic Code Generation
- ✅ **Full BIP39 Compliance** - Complete implementation of the BIP39 specification
- ✅ **Multi-Language Support** - 9 languages (English, Japanese, Korean, Spanish, French, Italian, Czech, Portuguese, Chinese)
- ✅ **Flexible Word Counts** - Support for 12, 15, 18, 21, and 24-word mnemonics
- ✅ **Cryptographically Secure** - Uses system CSPRNG for entropy generation
- ✅ **Type-Safe API** - Leverages Rust's type system for safety
- ✅ **Comprehensive Testing** - 184+ tests including unit, doc, and integration tests
- ✅ **Zero Unsafe Code** - Pure safe Rust implementation

### BIP32 - Hierarchical Deterministic Wallets
- ✅ **Full BIP32 Compliance** - Complete HD wallet implementation
- ✅ **BIP39 Integration** - Seamless integration with mnemonic generation
- ✅ **Hardened & Normal Derivation** - Both derivation types supported
- ✅ **Network Support** - Bitcoin mainnet and testnet
- ✅ **Extended Keys** - Full support for xprv/xpub serialization
- ✅ **Watch-Only Wallets** - Public key derivation without private keys
- ✅ **Memory Safety** - Secure memory handling with zeroization
- ✅ **Production Ready** - Validated against official test vectors

### BIP44 - Multi-Account Hierarchy
- ✅ **Multi-Account Support** - Manage multiple accounts per cryptocurrency
- ✅ **Multi-Coin Support** - Bitcoin, Ethereum, Litecoin, Dogecoin, and more
- ✅ **BIP Standards** - Support for BIP-44, BIP-49, BIP-84, and BIP-86
- ✅ **Account Caching** - Efficient account derivation with built-in caching
- ✅ **Builder Pattern** - Fluent API for wallet construction
- ✅ **Type Safety** - Strong typing for paths, chains, and coin types
- ✅ **Gap Limit** - BIP-44 compliant account discovery
- ✅ **Serialization** - Optional serde support for persistence
- ✅ **400+ Tests** - Comprehensive test coverage including edge cases

## 📦 Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
khodpay-bip39 = "0.2.0"
khodpay-bip32 = "0.2.0"
khodpay-bip44 = "0.1.0"
```

Or install via cargo:

```bash
cargo add khodpay-bip39
cargo add khodpay-bip32
cargo add khodpay-bip44
```

## 🔧 Quick Start

### Generate a BIP44 Multi-Coin Wallet (Recommended)

```rust
use khodpay_bip44::{Wallet, Purpose, CoinType, Language};
use khodpay_bip32::Network;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new wallet with a random mnemonic
    let mut wallet = Wallet::generate(
        12,  // 12-word mnemonic
        "",  // optional passphrase
        Language::English,
        Network::BitcoinMainnet,
    )?;
    
    println!("Recovery phrase: {}", wallet.mnemonic());
    
    // Get Bitcoin account (m/44'/0'/0')
    let btc_account = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;
    let btc_addr = btc_account.derive_external(0)?;  // m/44'/0'/0'/0/0
    println!("Bitcoin address: {}", btc_addr.public_key());
    
    // Get Ethereum account (m/44'/60'/0')
    let eth_account = wallet.get_account(Purpose::BIP44, CoinType::Ethereum, 0)?;
    let eth_addr = eth_account.derive_external(0)?;  // m/44'/60'/0'/0/0
    println!("Ethereum address: {}", eth_addr.public_key());
    
    Ok(())
}
```

### Generate a Wallet with BIP32 (Lower Level)

```rust
use khodpay_bip39::{Mnemonic, WordCount, Language};
use khodpay_bip32::{ExtendedPrivateKey, Network, DerivationPath};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a 12-word mnemonic
    let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;
    println!("Recovery phrase: {}", mnemonic.phrase());
    
    // Generate seed from mnemonic
    let seed = mnemonic.to_seed("optional passphrase")?;
    
    // Create master extended private key
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    
    // Derive BIP44 account key: m/44'/0'/0'
    let path = DerivationPath::from_str("m/44'/0'/0'")?;
    let account_key = master_key.derive_path(&path)?;
    
    println!("Account xprv: {}", account_key);
    println!("Account xpub: {}", account_key.to_extended_public_key());
    
    Ok(())
}
```

### Recover from Mnemonic

```rust
use khodpay_bip39::{Mnemonic, Language};
use khodpay_bip32::{ExtendedPrivateKey, Network};

fn recover_wallet(phrase: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Parse and validate mnemonic
    let mnemonic = Mnemonic::from_phrase(phrase, Language::English)?;
    
    // Generate seed (must use the same passphrase!)
    let seed = mnemonic.to_seed("")?;
    
    // Restore master key
    let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
    
    println!("Wallet recovered successfully!");
    Ok(())
}
```

### Multi-Account and SegWit Support

```rust
use khodpay_bip44::{Wallet, Purpose, CoinType};

fn multi_account_example(wallet: &mut Wallet) -> Result<(), Box<dyn std::error::Error>> {
    // Multiple Bitcoin accounts
    let account0 = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 0)?;
    let account1 = wallet.get_account(Purpose::BIP44, CoinType::Bitcoin, 1)?;
    
    // Native SegWit (BIP-84)
    let segwit = wallet.get_account(Purpose::BIP84, CoinType::Bitcoin, 0)?;
    let segwit_addr = segwit.derive_external(0)?;
    
    // Taproot (BIP-86)
    let taproot = wallet.get_account(Purpose::BIP86, CoinType::Bitcoin, 0)?;
    let taproot_addr = taproot.derive_external(0)?;
    
    Ok(())
}
```

### Watch-Only Wallet

```rust
use khodpay_bip32::{ExtendedPrivateKey, Network, ChildNumber, DerivationPath};
use std::str::FromStr;

fn create_watch_only() -> Result<(), Box<dyn std::error::Error>> {
    // Derive account key with hardened derivation
    let seed = b"your-secure-seed-bytes-here-at-least-16-bytes-long";
    let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet)?;
    
    let account_path = DerivationPath::from_str("m/44'/0'/0'")?;
    let account_key = master.derive_path(&account_path)?;
    
    // Export public key for watch-only wallet
    let account_pub = account_key.to_extended_public_key();
    
    // Derive receive addresses from public key only
    let first_receive = account_pub.derive_child(ChildNumber::Normal(0))?;
    let second_receive = account_pub.derive_child(ChildNumber::Normal(1))?;
    
    println!("Watch-only xpub: {}", account_pub);
    Ok(())
}
```

## 📚 Documentation

- [BIP39 API Documentation](https://docs.rs/khodpay-bip39)
- [BIP32 API Documentation](https://docs.rs/khodpay-bip32)
- [BIP44 API Documentation](https://docs.rs/khodpay-bip44)
- [Full Crate Documentation](https://docs.rs/khodpay-bip39)
- [Integration Guide](INTEGRATION_GUIDE.md)
- [Examples](examples/)

## 🏗️ Project Structure

```
khodpay-wallet/
├── crates/
│   ├── bip39/          # BIP39 mnemonic implementation
│   │   ├── src/
│   │   ├── tests/
│   │   └── benches/
│   ├── bip32/          # BIP32 HD wallet implementation
│   │   ├── src/
│   │   ├── tests/
│   │   └── benches/
│   └── bip44/          # BIP44 multi-account hierarchy
│       ├── src/
│       ├── tests/
│       └── benches/
├── examples/           # Usage examples
├── docs/               # Additional documentation
└── README.md
```

## 🔐 Security Considerations

### ⚠️ Critical Security Notes

1. **Entropy Generation**: Uses system CSPRNG (`rand::thread_rng()`) for secure random number generation
2. **Memory Safety**: Sensitive data is zeroized after use using the `zeroize` crate
3. **Mnemonic Storage**: NEVER store mnemonics in plain text or logs
4. **Passphrase Security**: Passphrases add a "25th word" for additional security
5. **Private Key Protection**: Never expose private keys over insecure channels
6. **Production Use**: Always conduct thorough security audits before production deployment

### Best Practices

- ✅ Use 24-word mnemonics for maximum security
- ✅ Use strong passphrases for additional protection
- ✅ Store mnemonics offline in secure locations
- ✅ Use hardened derivation for account-level keys
- ✅ Validate mnemonics before accepting user input
- ❌ Never log or transmit mnemonics
- ❌ Never store private keys in application state
- ❌ Never reuse addresses for privacy

## 🧪 Testing

The libraries include comprehensive test coverage:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific crate tests
cargo test -p khodpay-bip39
cargo test -p khodpay-bip32

# Run benchmarks
cargo bench
```

### Test Coverage

- **BIP39**: 184+ tests (unit, doc, and integration)
- **BIP32**: Comprehensive test vectors from official BIP32 specification
- **BIP44**: 400+ tests including integration, edge cases, and compatibility tests
- All test vectors from official BIP39, BIP32, and BIP44 specifications

## 📊 Performance

Benchmarking results on Apple M1:

```
BIP39 Mnemonic Generation (12 words):  ~50 μs
BIP39 Seed Derivation (PBKDF2):        ~100 ms
BIP32 Key Derivation (single):         ~15 μs
BIP32 Path Derivation (m/44'/0'/0'):   ~45 μs
```

Run benchmarks yourself:

```bash
cargo bench
```

## 🛣️ Roadmap

- [x] BIP39 implementation
- [x] BIP32 implementation
- [x] BIP44 multi-account hierarchy
- [x] BIP49 SegWit support (via BIP44 Purpose)
- [x] BIP84 Native SegWit support (via BIP44 Purpose)
- [x] BIP86 Taproot support (via BIP44 Purpose)
- [x] Multi-coin support (Bitcoin, Ethereum, Litecoin, etc.)
- [x] Account caching and discovery
- [x] Comprehensive test coverage
- [x] Documentation and examples
- [ ] Hardware wallet integration examples
- [ ] Additional language support
- [ ] WASM compilation support
- [ ] Address generation utilities
- [ ] Transaction signing support

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/khodpay/rust-wallet.git
cd rust-wallet

# Build the project
cargo build

# Run tests
cargo test

# Format code
cargo fmt

# Run clippy
cargo clippy
```

### Guidelines

- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass before submitting PR
- Add examples for new features

## 📄 License

This project is dual-licensed under:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

You may choose either license for your use.

## 🙏 Acknowledgments

- [Bitcoin BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [Bitcoin BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [Bitcoin BIP44 Specification](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [Bitcoin BIP49 Specification](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki)
- [Bitcoin BIP84 Specification](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)
- [Bitcoin BIP86 Specification](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)
- [SLIP-44 Coin Types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)

## 📞 Support

- 📧 Email: support@khodpay.com
- 🐛 Issues: [GitHub Issues](https://github.com/khodpay/rust-wallet/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/khodpay/rust-wallet/discussions)

## ⚠️ Disclaimer

This software is provided "as is", without warranty of any kind. Use at your own risk. The authors and contributors are not responsible for any loss of funds or other damages resulting from the use of this library. Always conduct thorough security audits before using in production environments.

---

**Built with ❤️ for the cryptocurrency community**
