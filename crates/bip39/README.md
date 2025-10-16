# 🔐 BIP39 - Mnemonic Code for Cryptocurrency Wallets

A comprehensive, production-ready Rust implementation of the BIP39 standard for generating deterministic keys in cryptocurrency wallets.

[![Crates.io](https://img.shields.io/crates/v/khodpay-bip39.svg)](https://crates.io/crates/khodpay-bip39)
[![Documentation](https://docs.rs/khodpay-bip39/badge.svg)](https://docs.rs/khodpay-bip39)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-149%20passing-brightgreen.svg)](#testing)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](../../LICENSE-MIT)

## 📖 Overview

BIP39 (Bitcoin Improvement Proposal 39) defines a method for creating mnemonic phrases (12-24 words) that can be used to generate deterministic cryptocurrency wallet keys. This implementation provides a safe, ergonomic, and fully-tested Rust API.

### ✨ Features

- ✅ **Full BIP39 Compliance** - Implements the complete BIP39 specification
- ✅ **Multi-Language Support** - 9 languages (English, Japanese, Korean, Spanish, French, Italian, Czech, Portuguese, Chinese Simplified)
- ✅ **Type-Safe API** - Leverages Rust's type system for safety
- ✅ **Comprehensive Testing** - 149 tests including unit, doc, and integration tests
- ✅ **Cryptographically Secure** - Uses system CSPRNG for entropy generation
- ✅ **Zero Unsafe Code** - Pure safe Rust implementation
- ✅ **Well Documented** - Extensive documentation and examples

## 🚀 Quick Start

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
khodpay-bip39 = "0.2.0"
```

Or via cargo:

```bash
cargo add khodpay-bip39
```

### Basic Usage

```rust
use khodpay_bip39::{Mnemonic, WordCount, Language};

// Generate a new 12-word mnemonic
let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;

// Display the phrase to the user (they should write it down!)
println!("Your recovery phrase: {}", mnemonic.phrase());

// Generate a cryptographic seed for key derivation
let seed = mnemonic.to_seed("optional passphrase")?;

// Use seed for BIP32 key derivation...
```

## 📚 Usage Examples

### Creating a New Wallet

```rust
use khodpay_bip39::{Mnemonic, WordCount, Language};

// Generate a new mnemonic with 24 words (highest security)
let mnemonic = Mnemonic::generate(WordCount::TwentyFour, Language::English)?;

// Show the phrase to the user
println!("🔑 Your recovery phrase (write this down!):");
println!("{}", mnemonic.phrase());

// Generate seed with passphrase for additional security
let seed = mnemonic.to_seed("my secure passphrase")?;
println!("✓ Wallet seed generated ({} bytes)", seed.len());
```

### Recovering a Wallet

```rust
use khodpay_bip39::{Mnemonic, Language};

// User enters their recovery phrase
let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Parse and validate the phrase
let mnemonic = Mnemonic::from_phrase(phrase, Language::English)?;

// Regenerate the seed (must use same passphrase!)
let seed = mnemonic.to_seed("my secure passphrase")?;

// Now derive keys from the seed...
```

### Creating from Known Entropy

```rust
use khodpay_bip39::{Mnemonic, Language};

// From hardware wallet or external entropy source
let entropy = [42u8; 32]; // 256 bits = 24 words

// Create mnemonic from entropy
let mnemonic = Mnemonic::new(&entropy, Language::English)?;

println!("Mnemonic: {}", mnemonic.phrase());
println!("Entropy: {:?}", mnemonic.entropy());
```

### Multi-Language Support

```rust
use khodpay_bip39::{Mnemonic, WordCount, Language};

// Generate Japanese mnemonic
let mnemonic_ja = Mnemonic::generate(WordCount::Twelve, Language::Japanese)?;
println!("日本語: {}", mnemonic_ja.phrase());

// Generate Spanish mnemonic
let mnemonic_es = Mnemonic::generate(WordCount::Twelve, Language::Spanish)?;
println!("Español: {}", mnemonic_es.phrase());
```

### All Word Count Options

```rust
use khodpay_bip39::{Mnemonic, WordCount, Language};

// 12 words = 128 bits entropy (standard)
let m12 = Mnemonic::generate(WordCount::Twelve, Language::English)?;

// 15 words = 160 bits entropy
let m15 = Mnemonic::generate(WordCount::Fifteen, Language::English)?;

// 18 words = 192 bits entropy
let m18 = Mnemonic::generate(WordCount::Eighteen, Language::English)?;

// 21 words = 224 bits entropy
let m21 = Mnemonic::generate(WordCount::TwentyOne, Language::English)?;

// 24 words = 256 bits entropy (maximum security)
let m24 = Mnemonic::generate(WordCount::TwentyFour, Language::English)?;
```

### Validating a Phrase

```rust
use khodpay_bip39::{validate_phrase_in_language, Language};

let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Validate the phrase
match validate_phrase_in_language(phrase, Language::English) {
    Ok(_) => println!("✓ Valid BIP39 phrase"),
    Err(e) => println!("✗ Invalid: {}", e),
}
```

### Using Utility Functions

```rust
use khodpay_bip39::{generate_mnemonic, phrase_to_seed, validate_phrase};

// Generate a phrase directly
let phrase = generate_mnemonic(WordCount::Twelve)?;

// Validate it
validate_phrase(&phrase)?;

// Generate seed from phrase
let seed = phrase_to_seed(&phrase, "passphrase")?;
```

## 🏗️ Architecture

### Core Types

- **`Mnemonic`** - Main struct representing a BIP39 mnemonic
  - `new(entropy, language)` - Create from raw entropy
  - `from_phrase(phrase, language)` - Parse existing phrase
  - `generate(word_count, language)` - Generate random mnemonic
  - `phrase()` - Get the mnemonic phrase
  - `entropy()` - Get the entropy bytes
  - `to_seed(passphrase)` - Generate cryptographic seed

- **`WordCount`** - Type-safe word count enum (12, 15, 18, 21, 24)

- **`Language`** - Supported languages enum

- **`Error`** - Comprehensive error types with helpful messages

### Module Structure

```
bip39/
├── src/
│   ├── lib.rs           # Public API exports
│   ├── error.rs         # Error types
│   ├── language.rs      # Language enum
│   ├── word_count.rs    # WordCount enum
│   ├── mnemonic.rs      # Core Mnemonic struct
│   └── utils.rs         # Utility functions
├── tests/
│   └── integration_tests.rs  # Integration tests
└── benches/
    └── benchmarks.rs    # Performance benchmarks
```

## 🔒 Security Considerations

### ⚠️ Important Security Notes

1. **Entropy Generation**: This library uses the system's cryptographically secure random number generator (`rand::thread_rng()`). Ensure your system's RNG is properly seeded.

2. **Mnemonic Storage**: 
   - Never store mnemonics in plain text
   - Never log or transmit mnemonics over insecure channels
   - Users should write down phrases on paper and store securely

3. **Passphrase Security**:
   - Passphrases add a "25th word" for additional security
   - If lost, the wallet cannot be recovered even with correct mnemonic
   - Use strong, memorable passphrases

4. **Memory Safety**:
   - Seeds and entropy should be zeroed after use in production
   - Consider using `zeroize` crate for sensitive data

### 🛡️ Best Practices

```rust
use khodpay_bip39::{Mnemonic, WordCount, Language};

// ✓ DO: Generate with maximum entropy
let mnemonic = Mnemonic::generate(WordCount::TwentyFour, Language::English)?;

// ✓ DO: Use passphrases for additional security
let seed = mnemonic.to_seed("strong passphrase")?;

// ✗ DON'T: Use weak entropy sources
// ✗ DON'T: Store mnemonics in application state
// ✗ DON'T: Log or transmit mnemonics
```

## 🧪 Testing

The crate includes comprehensive test coverage:

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run only unit tests
cargo test --lib

# Run only integration tests
cargo test --test integration_tests

# Run only doc tests
cargo test --doc

# Run benchmarks
cargo bench
```

### Test Statistics

- **Unit Tests**: 138 tests
- **Doc Tests**: 35 tests
- **Integration Tests**: 11 tests
- **Total**: 184 tests, all passing ✅

## ⚡ Performance

Benchmarks on Apple M1 (example):

```
generate_mnemonic_12_words    ~500 µs
generate_mnemonic_24_words    ~800 µs
from_phrase                   ~100 µs
to_seed (2048 iterations)     ~15 ms
validate_phrase               ~50 µs
```

Run benchmarks yourself:
```bash
cargo bench
```

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `cargo test`
2. Code is formatted: `cargo fmt`
3. No clippy warnings: `cargo clippy`
4. Documentation is updated
5. Add tests for new features

## 📄 License

This project is dual-licensed under:

- MIT License ([LICENSE-MIT](../../LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

You may choose either license for your use.

## 🔗 References

- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32 HD Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [PBKDF2 RFC](https://tools.ietf.org/html/rfc2898)

## 📮 Support

For bugs, questions, or feature requests, please open an issue on the repository.

---

**⚠️ Disclaimer**: This library handles sensitive cryptographic material. Use at your own risk. Always audit cryptographic code before using in production.
