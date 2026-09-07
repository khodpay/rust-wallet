//! # BIP39 - Mnemonic Code for Cryptocurrency Wallets
//!
//! A production-ready Rust implementation of the BIP39 standard for generating deterministic keys
//! in cryptocurrency wallets.
//!
//! ## Overview
//!
//! BIP39 (Bitcoin Improvement Proposal 39) defines a method for creating mnemonic phrases
//! (12-24 words) that can be used to generate deterministic cryptocurrency wallet keys.
//! This implementation provides a safe, ergonomic, and fully-tested Rust API.
//!
//! ## Features
//!
//! - **Full BIP39 Compliance** - Implements the complete BIP39 specification
//! - **Multi-Language Support** - 9 languages supported
//! - **Type-Safe API** - Leverages Rust's type system for safety
//! - **Comprehensive Testing** - 184+ tests including unit, doc, and integration tests
//! - **Cryptographically Secure** - Uses system CSPRNG for entropy generation
//! - **Zero Unsafe Code** - Pure safe Rust implementation
//!
//! ## Quick Start
//!
//! ```rust
//! use khodpay_bip39::{Mnemonic, WordCount, Language};
//!
//! // Generate a new 12-word mnemonic
//! let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;
//!
//! // Display the phrase (user should write this down!)
//! println!("Recovery phrase: {}", mnemonic.phrase());
//!
//! // Generate a cryptographic seed for key derivation
//! let seed = mnemonic.to_seed("optional passphrase")?;
//! # Ok::<(), khodpay_bip39::Error>(())
//! ```
//!
//! ## Core Types
//!
//! ### [`Mnemonic`]
//!
//! The main struct representing a BIP39 mnemonic phrase.
//!
//! **Constructors:**
//! - [`Mnemonic::new(entropy, language)`](Mnemonic::new) - Create from raw entropy bytes
//! - [`Mnemonic::from_phrase(phrase, language)`](Mnemonic::from_phrase) - Parse existing phrase
//! - [`Mnemonic::generate(word_count, language)`](Mnemonic::generate) - Generate random mnemonic
//!
//! **Methods:**
//! - [`phrase()`](Mnemonic::phrase) - Get the mnemonic phrase as a string
//! - [`entropy()`](Mnemonic::entropy) - Get the entropy bytes
//! - [`word_count()`](Mnemonic::word_count) - Get the word count
//! - [`to_seed(passphrase)`](Mnemonic::to_seed) - Generate cryptographic seed
//!
//! ### [`WordCount`]
//!
//! Type-safe enum for BIP39 word counts (12, 15, 18, 21, or 24 words).
//!
//! ### [`Language`]
//!
//! Enum for supported languages (English, Japanese, Korean, Spanish, French, Italian, Czech, Portuguese, Chinese Simplified).
//!
//! ### [`Error`]
//!
//! Comprehensive error type for all BIP39 operations.
//!
//! ## Usage Examples
//!
//! ### Creating a New Wallet
//!
//! ```rust
//! use khodpay_bip39::{Mnemonic, WordCount, Language};
//!
//! // Generate a new mnemonic with 24 words (highest security)
//! let mnemonic = Mnemonic::generate(WordCount::TwentyFour, Language::English)?;
//!
//! // Show the phrase to the user (they should write it down!)
//! println!("Your recovery phrase:");
//! println!("{}", mnemonic.phrase());
//!
//! // Generate seed with passphrase for additional security
//! let seed = mnemonic.to_seed("my secure passphrase")?;
//! # Ok::<(), khodpay_bip39::Error>(())
//! ```
//!
//! ### Recovering a Wallet
//!
//! ```rust
//! use khodpay_bip39::{Mnemonic, Language};
//!
//! // User enters their recovery phrase
//! let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//!
//! // Parse and validate the phrase
//! let mnemonic = Mnemonic::from_phrase(phrase, Language::English)?;
//!
//! // Regenerate the seed (must use same passphrase!)
//! let seed = mnemonic.to_seed("my secure passphrase")?;
//! # Ok::<(), khodpay_bip39::Error>(())
//! ```
//!
//! ### Creating from Known Entropy
//!
//! ```rust
//! use khodpay_bip39::{Mnemonic, Language};
//!
//! // From hardware wallet or external entropy source
//! let entropy = [42u8; 32]; // 256 bits = 24 words
//!
//! // Create mnemonic from entropy
//! let mnemonic = Mnemonic::new(&entropy, Language::English)?;
//!
//! println!("Mnemonic: {}", mnemonic.phrase());
//! # Ok::<(), khodpay_bip39::Error>(())
//! ```
//!
//! ### Using Utility Functions
//!
//! ```rust
//! use khodpay_bip39::{generate_mnemonic, validate_phrase, phrase_to_seed, WordCount};
//!
//! // Generate a phrase directly
//! let phrase = generate_mnemonic(WordCount::Twelve)?;
//!
//! // Validate it
//! validate_phrase(&phrase)?;
//!
//! // Generate seed from phrase
//! let seed = phrase_to_seed(&phrase, "passphrase")?;
//! # Ok::<(), khodpay_bip39::Error>(())
//! ```
//!
//! ## Security Considerations
//!
//! ### ⚠️ Important Security Notes
//!
//! 1. **Entropy Generation**: Uses system CSPRNG (`rand::rngs::OsRng`)
//! 2. **Mnemonic Storage**: Never store mnemonics in plain text
//! 3. **Passphrase Security**: Passphrases add a "25th word" for additional security
//! 4. **Memory Safety**: Consider zeroing sensitive data after use
//!
//! ### Best Practices
//!
//! ```rust
//! use khodpay_bip39::{Mnemonic, WordCount, Language};
//!
//! // ✓ DO: Generate with maximum entropy
//! let mnemonic = Mnemonic::generate(WordCount::TwentyFour, Language::English)?;
//!
//! // ✓ DO: Use passphrases for additional security
//! let seed = mnemonic.to_seed("strong passphrase")?;
//!
//! // ✗ DON'T: Store mnemonics in application state
//! // ✗ DON'T: Log or transmit mnemonics
//! # Ok::<(), khodpay_bip39::Error>(())
//! ```
//!
//! ## Testing
//!
//! The crate includes comprehensive test coverage:
//!
//! - **Unit Tests**: 138 tests covering all modules
//! - **Doc Tests**: 35 tests in documentation
//! - **Integration Tests**: 11 end-to-end workflow tests
//!
//! Run tests with:
//! ```bash
//! cargo test
//! ```
//!
//! ## References
//!
//! - [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
//! - [BIP32 HD Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

// Module declarations
mod error;
mod language;
mod mnemonic;
mod utils;
mod word_count;

// Public re-exports
pub use error::{Error, Result};
pub use language::Language;
pub use mnemonic::Mnemonic;
pub use utils::{
    generate_mnemonic, generate_mnemonic_in_language, phrase_to_seed, phrase_to_seed_in_language,
    validate_phrase, validate_phrase_in_language,
};
pub use word_count::WordCount;
