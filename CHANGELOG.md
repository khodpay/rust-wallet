# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2024-12-01

### Changed

#### BIP39
- 🔄 **Switched to `OsRng` for entropy generation** - Replaced `rand::thread_rng()` with `rand::rngs::OsRng` for reliable random number generation on mobile devices and static library builds

### Fixed
- 🐛 Fixed potential issues with thread-local RNG on iOS/Android static library targets

## [0.3.0] - 2024-11-02

### Added

#### BIP44 (New Crate)
- ✨ **Full BIP-44 specification implementation** - Multi-account hierarchy for deterministic wallets
- ✨ **Multi-coin support** - Bitcoin, Ethereum, Litecoin, Dogecoin, and all SLIP-44 registered coins
- ✨ **Multi-account support** - Manage multiple accounts per cryptocurrency
- ✨ **BIP standards support** - BIP-44, BIP-49, BIP-84, and BIP-86 via Purpose enum
- ✨ **Account caching** - Efficient account derivation with built-in caching mechanism
- ✨ **Builder pattern** - Fluent API for wallet construction with `WalletBuilder`
- ✨ **Type-safe paths** - Strong typing for derivation paths, chains, and coin types
- ✨ **Path parsing** - Parse and validate BIP-44 path strings (e.g., "m/44'/0'/0'/0/0")
- ✨ **Account discovery** - BIP-44 compliant gap limit checking for wallet recovery
- ✨ **Address iteration** - Iterator pattern for efficient address generation
- ✨ **Batch derivation** - Generate multiple addresses efficiently with `derive_address_range`
- ✨ **Serialization support** - Optional serde feature for persistence
- ✨ **Comprehensive testing** - 400+ tests including unit, integration, edge cases, and compatibility tests
- ✨ **Performance benchmarks** - Benchmark suite for account and address derivation
- ✨ **Complete documentation** - Full API docs with examples and usage guides

#### Features
- 🎯 **Wallet types**: Generate new wallets or recover from mnemonic phrases
- 🎯 **Chain support**: External (receiving) and internal (change) address chains
- 🎯 **Network support**: Bitcoin mainnet and testnet via BIP32 integration
- 🎯 **Memory safety**: Secure handling of sensitive key material
- 🎯 **Zero unsafe code**: 100% safe Rust implementation

#### Compatibility
- ✅ Compatible with Electrum, Ledger, Trezor, MetaMask, Trust Wallet, and Exodus
- ✅ Follows official BIP-44 specification
- ✅ Validated against standard test vectors

## [0.2.0] - 2024-10-16

### Changed
- 🔄 Updated repository URL to `https://github.com/khodpay/rust-wallet`
- 🔄 Updated MSRV to 1.81 (required by `half` crate dependency)
- ✨ Fixed all 40+ clippy warnings across workspace
- ✨ Fixed code formatting issues (trailing whitespace)
- ✨ Fixed benchmark seed lengths to 64 bytes (BIP32 maximum)
- 🎯 Improved CI/CD pipeline with better caching and workflow

### Fixed
- 🐛 Resolved CI failures on all platforms (Ubuntu, macOS, Windows)
- 🐛 Fixed needless borrows in digest operations
- 🐛 Fixed unnecessary clones on Copy types
- 🐛 Fixed benchmark seed length errors

## [0.1.0] - 2024-10-16

### Added

#### BIP39
- ✨ Full BIP39 specification implementation
- ✨ Support for 12, 15, 18, 21, and 24-word mnemonics
- ✨ Multi-language support (9 languages: English, Japanese, Korean, Spanish, French, Italian, Czech, Portuguese, Chinese Simplified)
- ✨ Cryptographically secure mnemonic generation using system CSPRNG
- ✨ PBKDF2-HMAC-SHA512 seed derivation with passphrase support
- ✨ Type-safe API with `WordCount` and `Language` enums
- ✨ Comprehensive error handling with descriptive error types
- ✨ Utility functions for common operations
- ✨ 184+ tests including unit, doc, and integration tests
- ✨ Performance benchmarks
- ✨ Complete documentation with examples

#### BIP32
- ✨ Full BIP32 hierarchical deterministic wallet implementation
- ✨ Master key generation from seed
- ✨ Extended private and public key support
- ✨ Hardened and normal child key derivation
- ✨ Derivation path parsing (e.g., "m/44'/0'/0'")
- ✨ Bitcoin mainnet and testnet network support
- ✨ Base58Check serialization (xprv/xpub format)
- ✨ Fingerprint calculation (HASH160)
- ✨ Watch-only wallet support via public key derivation
- ✨ Integration with BIP39 for mnemonic-based key generation
- ✨ Memory safety with zeroization of sensitive data
- ✨ Comprehensive test coverage including official BIP32 test vectors
- ✨ Performance benchmarks
- ✨ Full API documentation

#### Project
- 📄 Dual MIT/Apache-2.0 licensing
- 📚 Comprehensive README files for repository and each crate
- 📖 Integration guide with usage examples
- 🔧 Workspace configuration for multi-crate project
- 🧪 Extensive test coverage across all modules
- ⚡ Performance benchmarks
- 📝 API documentation
- 🔐 Security best practices documentation

### Security
- ✅ Zero unsafe code - pure safe Rust implementation
- ✅ Cryptographically secure random number generation
- ✅ Memory zeroization for sensitive data
- ✅ Type-safe API preventing common errors
- ✅ Validated against official BIP39 and BIP32 test vectors

### Performance
- ⚡ Optimized key derivation using secp256k1
- ⚡ Efficient PBKDF2 implementation
- ⚡ Minimal allocations
- ⚡ Zero-copy operations where possible

[Unreleased]: https://github.com/khodpay/rust-wallet/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/khodpay/rust-wallet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/khodpay/rust-wallet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/khodpay/rust-wallet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/khodpay/rust-wallet/releases/tag/v0.1.0
