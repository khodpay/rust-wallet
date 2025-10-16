# BIP32 - Hierarchical Deterministic Wallets

[![Crates.io](https://img.shields.io/crates/v/khodpay-bip32.svg)](https://crates.io/crates/khodpay-bip32)
[![Documentation](https://docs.rs/khodpay-bip32/badge.svg)](https://docs.rs/khodpay-bip32)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](../../LICENSE-MIT)

A production-ready Rust implementation of the BIP32 standard for hierarchical deterministic wallets in cryptocurrency applications.

## Features

- ✅ **Full BIP32 Compliance** - Implements the complete [BIP32 specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- ✅ **Type-Safe API** - Leverages Rust's type system for compile-time safety
- ✅ **BIP39 Integration** - Seamlessly works with BIP39 mnemonics
- ✅ **Hardened & Normal Derivation** - Supports both derivation types
- ✅ **Network Support** - Bitcoin mainnet and testnet
- ✅ **Zero Unsafe Code** - Pure safe Rust implementation
- ✅ **Production Ready** - Validated against official test vectors
- ✅ **Cross-Compatible** - Interoperable with major wallet implementations (Trezor, Ledger, Electrum, Bitcoin Core)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
khodpay-bip32 = "0.2.0"
khodpay-bip39 = "0.2.0"  # For mnemonic support
```

## Quick Start

### Basic Usage

```rust
use khodpay_bip32::{ExtendedPrivateKey, Network, DerivationPath};
use khodpay_bip39::{Mnemonic, WordCount, Language};
use std::str::FromStr;

// Generate a mnemonic (using BIP39)
let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;

// Create master extended private key from mnemonic
let master_key = ExtendedPrivateKey::from_mnemonic(
    &mnemonic,
    None,  // Optional passphrase
    Network::BitcoinMainnet
)?;

// Derive child keys using a BIP-44 path
let path = DerivationPath::from_str("m/44'/0'/0'")?;
let account_key = master_key.derive_path(&path)?;

println!("Account xprv: {}", account_key);
println!("Account xpub: {}", account_key.to_extended_public_key());
```

### Derive from Seed

```rust
use khodpay_bip32::{ExtendedPrivateKey, Network};

// Use a seed directly (typically from BIP39)
let seed = b"your-secure-seed-bytes-here-at-least-16-bytes-long";
let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet)?;

// Get the extended public key
let master_pub = master.to_extended_public_key();
println!("Master xpub: {}", master_pub);
```

### Watch-Only Wallets (Public Key Derivation)

```rust
use khodpay_bip32::{ExtendedPrivateKey, Network, DerivationPath, ChildNumber};
use std::str::FromStr;

let seed = b"your-secure-seed-bytes-here-at-least-16-bytes-long";
let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet)?;

// Derive account-level key (with hardened derivation)
let account_path = DerivationPath::from_str("m/44'/0'/0'")?;
let account_key = master.derive_path(&account_path)?;

// Get the extended public key for watch-only wallet
let account_pub = account_key.to_extended_public_key();

// Now derive receive addresses from public key only (no private key needed)
let first_address = account_pub.derive_child(ChildNumber::Normal(0))?;
println!("First receive address xpub: {}", first_address);
```

### Generate Multiple Addresses

```rust
use khodpay_bip32::{ExtendedPrivateKey, Network, DerivationPath, ChildNumber};
use std::str::FromStr;

let seed = b"your-secure-seed-bytes-here-at-least-16-bytes-long";
let master = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet)?;

// BIP-44 Bitcoin account 0, external chain (receive addresses)
let path = DerivationPath::from_str("m/44'/0'/0'/0")?;
let receive_chain = master.derive_path(&path)?;

// Generate first 5 receiving addresses
for i in 0..5 {
    let address_key = receive_chain.derive_child(ChildNumber::Normal(i))?;
    let address_pub = address_key.to_extended_public_key();
    println!("Address {}: {}", i, address_pub);
}
```

## Common Derivation Paths

Following standard BIP specifications:

| Standard | Path | Purpose |
|----------|------|---------|
| **BIP44** | `m/44'/0'/0'` | Multi-account hierarchy for Bitcoin |
| **BIP49** | `m/49'/0'/0'` | SegWit (P2WPKH-nested-in-P2SH) |
| **BIP84** | `m/84'/0'/0'` | Native SegWit (P2WPKH) |

### BIP-44 Structure

```
m / purpose' / coin_type' / account' / change / address_index
```

- **purpose'** - 44' for BIP-44
- **coin_type'** - 0' for Bitcoin, 1' for Bitcoin Testnet
- **account'** - Account index (0' for first account)
- **change** - 0 for external (receive), 1 for internal (change)
- **address_index** - Address index (0, 1, 2, ...)

**Example**: `m/44'/0'/0'/0/0` = First receiving address of the first account

## API Overview

### Core Types

- **`ExtendedPrivateKey`** - Extended private key with derivation capabilities
- **`ExtendedPublicKey`** - Extended public key for watch-only wallets
- **`DerivationPath`** - Path specification for key derivation
- **`ChildNumber`** - Individual derivation step (normal or hardened)
- **`Network`** - Bitcoin mainnet or testnet configuration

### Key Methods

```rust
// Master key generation
ExtendedPrivateKey::from_seed(seed, network)?
ExtendedPrivateKey::from_mnemonic(mnemonic, passphrase, network)?

// Key derivation
master_key.derive_path(&path)?
master_key.derive_child(child_number)?

// Public key conversion
private_key.to_extended_public_key()

// Serialization
key.to_string()  // Base58Check format (xprv/xpub)
ExtendedPrivateKey::from_str(xprv_string)?
```

## Security Considerations

🔐 **Important Security Guidelines**:

1. **Use Cryptographically Secure Seeds** - Always use proper random number generators
2. **Protect Private Keys** - Store private keys and seeds securely
3. **Use Hardened Derivation** - Use hardened derivation (`'` or `H`) for account-level keys
4. **Never Expose Seeds** - Never transmit seeds or private keys over insecure channels
5. **Zeroize Sensitive Data** - This library uses `zeroize` to clear sensitive data from memory

### Hardened vs Normal Derivation

- **Hardened** (`m/44'/0'/0'`): More secure, requires private key, prevents parent key exposure
- **Normal** (`m/44'/0'/0'/0/0`): Allows public key derivation, useful for watch-only wallets

**Best Practice**: Use hardened derivation for upper levels (purpose, coin type, account) and normal derivation for address generation.

## Compatibility

This implementation is fully compatible with:

- ✅ **Hardware Wallets**: Trezor, Ledger
- ✅ **Software Wallets**: Electrum, Bitcoin Core, Bitpay/Bitcore
- ✅ **Standards**: BIP32, BIP39, BIP44, BIP49, BIP84
- ✅ **Libraries**: btcsuite/btcutil (Go), bitcoinjs-lib (JavaScript)

All keys are interoperable and can be imported/exported across different wallet implementations.

## Testing

This library includes comprehensive test coverage:

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_bip44_derivation

# Run doc tests
cargo test --doc
```

Test coverage includes:
- ✅ Official BIP32 test vectors (all 4 vectors)
- ✅ Cross-compatibility with major implementations
- ✅ Edge cases (leading zeros, maximum indices)
- ✅ Error handling and validation

## Documentation

Full API documentation is available at [docs.rs/bip32](https://docs.rs/bip32).

Build documentation locally:

```bash
cargo doc --open --no-deps --package khodpay-bip32
```

## Examples

Additional examples can be found in the `examples/` directory:

- `wallet_creation.rs` - Complete wallet creation workflow
- `key_derivation.rs` - Various derivation patterns
- `watch_only.rs` - Public key derivation for watch-only wallets

Run examples:

```bash
cargo run --example wallet_creation
```

## Performance

The library is optimized for both performance and security:

- Efficient key derivation using `secp256k1`
- Minimal allocations
- Zero-copy operations where possible
- Constant-time operations for sensitive data

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `cargo test`
2. Code is formatted: `cargo fmt`
3. No clippy warnings: `cargo clippy`
4. Documentation is updated

## License

This project is dual-licensed under:

- MIT License ([LICENSE-MIT](../../LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

You may choose either license for your use.

## References

- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP44 Specification](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [BIP49 Specification](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki)
- [BIP84 Specification](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)

## Support

- 📖 [Documentation](https://docs.rs/khodpay-bip32)
- 🐛 [Issue Tracker](https://github.com/your-repo/issues)
- 💬 [Discussions](https://github.com/your-repo/discussions)

---

**Made with ❤️ for the Bitcoin and cryptocurrency community**
