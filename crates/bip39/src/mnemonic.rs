//! Core Mnemonic struct for BIP39 mnemonic phrase management.
//!
//! This module provides the [`Mnemonic`] struct, which represents a BIP39 mnemonic phrase
//! along with its associated metadata. The struct provides type-safe access to mnemonic
//! phrases and ensures all operations maintain BIP39 compliance.
//!
//! # Overview
//!
//! A [`Mnemonic`] encapsulates:
//! - The mnemonic phrase as a string
//! - The language of the mnemonic
//! - The entropy used to generate the mnemonic
//!
//! # Examples
//!
//! ```rust
//! use bip39::{Mnemonic, WordCount, Language};
//!
//! // Generate a new mnemonic (will be implemented in later tasks)
//! // let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English).unwrap();
//!
//! // Parse an existing mnemonic phrase (will be implemented in later tasks)
//! // let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! // let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
//! ```

use crate::{Language, WordCount};

/// A BIP39 mnemonic phrase with associated metadata.
///
/// This struct represents a validated BIP39 mnemonic phrase and provides
/// type-safe access to the phrase, its language, and the underlying entropy.
///
/// # Structure
///
/// The `Mnemonic` struct stores:
/// - **phrase**: The mnemonic phrase as a space-separated string
/// - **language**: The language of the mnemonic phrase
/// - **entropy**: The raw entropy bytes used to generate the mnemonic
/// - **word_count**: The number of words in the mnemonic (12, 15, 18, 21, or 24)
///
/// # Invariants
///
/// A `Mnemonic` instance guarantees:
/// - The phrase is a valid BIP39 mnemonic
/// - The phrase matches the stored entropy and checksum
/// - The word count corresponds to the entropy length
/// - All words are from the specified language's wordlist
///
/// # Construction
///
/// Mnemonics can be created through several constructors:
/// - [`Mnemonic::new()`] - Create from raw entropy (Task 14)
/// - [`Mnemonic::from_phrase()`] - Parse an existing phrase (Task 16)
/// - [`Mnemonic::generate()`] - Generate a new random mnemonic (Task 18)
///
/// # Examples
///
/// ```rust
/// use bip39::{Mnemonic, WordCount, Language};
///
/// // Example will work once constructors are implemented
/// // let entropy = [0u8; 16]; // 128 bits for 12 words
/// // let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
/// // assert_eq!(mnemonic.word_count(), WordCount::Twelve);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mnemonic {
    /// The mnemonic phrase as a space-separated string.
    /// Contains 12, 15, 18, 21, or 24 words from the specified language's wordlist.
    phrase: String,

    /// The language of the mnemonic phrase.
    /// Determines which BIP39 wordlist is used for validation and word selection.
    language: Language,

    /// The raw entropy bytes used to generate this mnemonic.
    /// Length must be 16, 20, 24, 28, or 32 bytes (128, 160, 192, 224, or 256 bits).
    /// The mnemonic is derived from this entropy plus a checksum.
    entropy: Vec<u8>,

    /// The number of words in the mnemonic phrase.
    /// Valid values are 12, 15, 18, 21, or 24 words.
    /// This is derived from the entropy length.
    word_count: WordCount,
}
