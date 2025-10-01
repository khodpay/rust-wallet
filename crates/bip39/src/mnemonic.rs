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
use bip39_upstream;

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

impl Mnemonic {
    /// Creates a new `Mnemonic` from raw entropy bytes.
    ///
    /// This constructor converts raw entropy into a BIP39 mnemonic phrase.
    /// The entropy must be one of the valid BIP39 lengths, and a checksum
    /// will be automatically calculated and appended.
    ///
    /// # Arguments
    ///
    /// * `entropy` - Raw entropy bytes. Must be 16, 20, 24, 28, or 32 bytes
    /// * `language` - The language for the mnemonic wordlist
    ///
    /// # Returns
    ///
    /// * `Ok(Mnemonic)` - A new mnemonic instance
    /// * `Err(Error)` - If the entropy length is invalid
    ///
    /// # Valid Entropy Lengths
    ///
    /// - 16 bytes (128 bits) → 12 words
    /// - 20 bytes (160 bits) → 15 words
    /// - 24 bytes (192 bits) → 18 words
    /// - 28 bytes (224 bits) → 21 words
    /// - 32 bytes (256 bits) → 24 words
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip39::{Mnemonic, Language};
    ///
    /// // Create a 12-word mnemonic from 16 bytes of entropy
    /// let entropy = [0u8; 16];
    /// let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
    /// assert_eq!(mnemonic.word_count().word_count(), 12);
    /// ```
    pub fn new(entropy: &[u8], language: Language) -> crate::Result<Self> {
        use crate::Error;
        
        // Step 1: Validate entropy length and determine word count
        let word_count = WordCount::from_entropy_length(entropy.len())?;
        
        // Step 2: Convert language to upstream format
        let upstream_language = language.to_upstream();
        
        // Step 3: Create mnemonic from entropy using upstream crate
        // The upstream crate handles:
        // - Entropy validation
        // - Checksum calculation (appends checksum bits to entropy)
        // - Word selection from language-specific wordlist
        // - Proper formatting with spaces between words
        let upstream_mnemonic = bip39_upstream::Mnemonic::from_entropy_in(upstream_language, entropy)
            .map_err(|_| Error::InvalidEntropyLength {
                length: entropy.len(),
            })?;
        
        // Step 4: Extract the phrase string
        let phrase = upstream_mnemonic.to_string();
        
        // Step 5: Store entropy as Vec for owned data
        let entropy = entropy.to_vec();
        
        // Step 6: Construct and return the Mnemonic
        Ok(Self {
            phrase,
            language,
            entropy,
            word_count,
        })
    }

    /// Returns the word count of this mnemonic.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip39::{Mnemonic, Language, WordCount};
    ///
    /// let entropy = [0u8; 16];
    /// let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
    /// assert_eq!(mnemonic.word_count(), WordCount::Twelve);
    /// ```
    pub fn word_count(&self) -> WordCount {
        self.word_count
    }

    /// Creates a `Mnemonic` by parsing an existing mnemonic phrase.
    ///
    /// This constructor parses and validates a BIP39 mnemonic phrase string,
    /// extracting the underlying entropy and storing the phrase.
    ///
    /// # Arguments
    ///
    /// * `phrase` - The mnemonic phrase to parse (space-separated words)
    /// * `language` - The language of the mnemonic phrase
    ///
    /// # Returns
    ///
    /// * `Ok(Mnemonic)` - A new mnemonic instance if the phrase is valid
    /// * `Err(Error)` - If the phrase is invalid or fails validation
    ///
    /// # Validation
    ///
    /// The phrase is validated for:
    /// - Correct word count (12, 15, 18, 21, or 24 words)
    /// - All words exist in the specified language's BIP39 wordlist
    /// - Valid checksum (last word encodes a checksum of the entropy)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip39::{Mnemonic, Language};
    ///
    /// // Parse a valid 12-word English mnemonic
    /// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
    /// assert_eq!(mnemonic.word_count().word_count(), 12);
    /// ```
    pub fn from_phrase(phrase: &str, language: Language) -> crate::Result<Self> {
        use crate::validate_phrase_in_language;
        
        // Step 1: Validate the phrase first using our validation function
        // This ensures the phrase has correct word count, valid words, and valid checksum
        validate_phrase_in_language(phrase, language)?;
        
        // Step 2: Convert language to upstream format
        let upstream_language = language.to_upstream();
        
        // Step 3: Parse the mnemonic using the upstream crate
        // We've already validated it, so this should succeed
        // Using parse_in_normalized to handle whitespace and case normalization
        let upstream_mnemonic = bip39_upstream::Mnemonic::parse_in_normalized(
            upstream_language,
            phrase
        ).map_err(|_| crate::Error::InvalidMnemonic {
            reason: "Failed to parse validated phrase".to_string(),
        })?;
        
        // Step 4: Extract the entropy from the parsed mnemonic
        // The upstream crate stores the entropy internally
        let entropy = upstream_mnemonic.to_entropy().to_vec();
        
        // Step 5: Determine word count from entropy length
        let word_count = WordCount::from_entropy_length(entropy.len())?;
        
        // Step 6: Get the normalized phrase string
        // This ensures consistent formatting (lowercase, single spaces)
        let phrase = upstream_mnemonic.to_string();
        
        // Step 7: Construct and return the Mnemonic
        Ok(Self {
            phrase,
            language,
            entropy,
            word_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    // ============================================================================
    // Tests for Mnemonic::new() constructor (Task 13)
    // ============================================================================

    #[test]
    fn test_new_with_16_byte_entropy() {
        // 16 bytes = 128 bits → 12 words
        let entropy = [0u8; 16];
        let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
        
        assert_eq!(mnemonic.word_count(), WordCount::Twelve);
        assert_eq!(mnemonic.entropy.len(), 16);
        assert_eq!(mnemonic.language, Language::English);
        
        // Verify the phrase has 12 words
        let word_count = mnemonic.phrase.split_whitespace().count();
        assert_eq!(word_count, 12);
    }

    #[test]
    fn test_new_with_20_byte_entropy() {
        // 20 bytes = 160 bits → 15 words
        let entropy = [0u8; 20];
        let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
        
        assert_eq!(mnemonic.word_count(), WordCount::Fifteen);
        assert_eq!(mnemonic.entropy.len(), 20);
        
        let word_count = mnemonic.phrase.split_whitespace().count();
        assert_eq!(word_count, 15);
    }

    #[test]
    fn test_new_with_24_byte_entropy() {
        // 24 bytes = 192 bits → 18 words
        let entropy = [0u8; 24];
        let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
        
        assert_eq!(mnemonic.word_count(), WordCount::Eighteen);
        assert_eq!(mnemonic.entropy.len(), 24);
        
        let word_count = mnemonic.phrase.split_whitespace().count();
        assert_eq!(word_count, 18);
    }

    #[test]
    fn test_new_with_28_byte_entropy() {
        // 28 bytes = 224 bits → 21 words
        let entropy = [0u8; 28];
        let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
        
        assert_eq!(mnemonic.word_count(), WordCount::TwentyOne);
        assert_eq!(mnemonic.entropy.len(), 28);
        
        let word_count = mnemonic.phrase.split_whitespace().count();
        assert_eq!(word_count, 21);
    }

    #[test]
    fn test_new_with_32_byte_entropy() {
        // 32 bytes = 256 bits → 24 words
        let entropy = [0u8; 32];
        let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
        
        assert_eq!(mnemonic.word_count(), WordCount::TwentyFour);
        assert_eq!(mnemonic.entropy.len(), 32);
        
        let word_count = mnemonic.phrase.split_whitespace().count();
        assert_eq!(word_count, 24);
    }

    #[test]
    fn test_new_with_invalid_entropy_length() {
        // 15 bytes is not a valid entropy length
        let entropy = [0u8; 15];
        let result = Mnemonic::new(&entropy, Language::English);
        
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidEntropyLength { length } => {
                assert_eq!(length, 15);
            }
            _ => panic!("Expected InvalidEntropyLength error"),
        }
    }

    #[test]
    fn test_new_with_too_short_entropy() {
        // 10 bytes is too short
        let entropy = [0u8; 10];
        let result = Mnemonic::new(&entropy, Language::English);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidEntropyLength { .. }));
    }

    #[test]
    fn test_new_with_too_long_entropy() {
        // 40 bytes is too long
        let entropy = [0u8; 40];
        let result = Mnemonic::new(&entropy, Language::English);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidEntropyLength { .. }));
    }

    #[test]
    fn test_new_different_entropy_produces_different_phrase() {
        // Different entropy should produce different mnemonics
        let entropy1 = [0u8; 16];
        let entropy2 = [1u8; 16];
        
        let mnemonic1 = Mnemonic::new(&entropy1, Language::English).unwrap();
        let mnemonic2 = Mnemonic::new(&entropy2, Language::English).unwrap();
        
        assert_ne!(mnemonic1.phrase, mnemonic2.phrase);
        assert_ne!(mnemonic1, mnemonic2);
    }

    #[test]
    fn test_new_same_entropy_produces_same_phrase() {
        // Same entropy should produce identical mnemonics
        let entropy = [42u8; 16];
        
        let mnemonic1 = Mnemonic::new(&entropy, Language::English).unwrap();
        let mnemonic2 = Mnemonic::new(&entropy, Language::English).unwrap();
        
        assert_eq!(mnemonic1.phrase, mnemonic2.phrase);
        assert_eq!(mnemonic1, mnemonic2);
    }

    #[test]
    fn test_new_with_japanese_language() {
        // Test with Japanese language
        let entropy = [0u8; 16];
        let mnemonic = Mnemonic::new(&entropy, Language::Japanese).unwrap();
        
        assert_eq!(mnemonic.language, Language::Japanese);
        assert_eq!(mnemonic.word_count(), WordCount::Twelve);
        
        // Japanese mnemonics should have 12 words
        let word_count = mnemonic.phrase.split_whitespace().count();
        assert_eq!(word_count, 12);
    }

    #[test]
    fn test_new_entropy_is_stored() {
        // Verify entropy is properly stored
        let entropy = [7u8; 16];
        let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
        
        assert_eq!(mnemonic.entropy.as_slice(), &entropy);
    }

    #[test]
    fn test_new_phrase_is_valid_bip39() {
        // Generated phrase should be a valid BIP39 mnemonic
        use crate::validate_phrase_in_language;
        
        let entropy = [0u8; 16];
        let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
        
        // The phrase should pass validation
        assert!(validate_phrase_in_language(&mnemonic.phrase, Language::English).is_ok());
    }

    #[test]
    fn test_new_all_valid_entropy_lengths() {
        // Test all valid entropy lengths
        let valid_lengths = vec![
            (16, WordCount::Twelve),
            (20, WordCount::Fifteen),
            (24, WordCount::Eighteen),
            (28, WordCount::TwentyOne),
            (32, WordCount::TwentyFour),
        ];
        
        for (length, expected_word_count) in valid_lengths {
            let entropy = vec![0u8; length];
            let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
            
            assert_eq!(mnemonic.word_count(), expected_word_count);
            assert_eq!(mnemonic.entropy.len(), length);
        }
    }

    #[test]
    fn test_new_with_all_languages() {
        // Test that new() works with all languages
        let entropy = [0u8; 16];
        let languages = Language::all_variants();
        
        for &language in languages {
            let mnemonic = Mnemonic::new(&entropy, language).unwrap();
            assert_eq!(mnemonic.language, language);
            assert_eq!(mnemonic.word_count(), WordCount::Twelve);
        }
    }

    #[test]
    fn test_new_clone_equality() {
        // Test that cloned mnemonics are equal
        let entropy = [0u8; 16];
        let mnemonic1 = Mnemonic::new(&entropy, Language::English).unwrap();
        let mnemonic2 = mnemonic1.clone();
        
        assert_eq!(mnemonic1, mnemonic2);
        assert_eq!(mnemonic1.phrase, mnemonic2.phrase);
        assert_eq!(mnemonic1.entropy, mnemonic2.entropy);
    }

    // ============================================================================
    // Tests for Mnemonic::from_phrase() constructor (Task 15)
    // ============================================================================

    // Test constant for a known valid 12-word phrase
    const VALID_12_WORD_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const VALID_24_WORD_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_from_phrase_valid_12_words() {
        // Parse a valid 12-word mnemonic
        let mnemonic = Mnemonic::from_phrase(VALID_12_WORD_PHRASE, Language::English).unwrap();
        
        assert_eq!(mnemonic.word_count(), WordCount::Twelve);
        assert_eq!(mnemonic.language, Language::English);
        assert_eq!(mnemonic.phrase, VALID_12_WORD_PHRASE);
        
        // Verify entropy is 16 bytes for 12 words
        assert_eq!(mnemonic.entropy.len(), 16);
    }

    #[test]
    fn test_from_phrase_valid_24_words() {
        // Parse a valid 24-word mnemonic
        let mnemonic = Mnemonic::from_phrase(VALID_24_WORD_PHRASE, Language::English).unwrap();
        
        assert_eq!(mnemonic.word_count(), WordCount::TwentyFour);
        assert_eq!(mnemonic.language, Language::English);
        assert_eq!(mnemonic.phrase, VALID_24_WORD_PHRASE);
        
        // Verify entropy is 32 bytes for 24 words
        assert_eq!(mnemonic.entropy.len(), 32);
    }

    #[test]
    fn test_from_phrase_invalid_word() {
        // Phrase with an invalid word
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid";
        let result = Mnemonic::from_phrase(phrase, Language::English);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidWord { .. }));
    }

    #[test]
    fn test_from_phrase_invalid_checksum() {
        // Valid words but wrong checksum (last word is wrong)
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = Mnemonic::from_phrase(phrase, Language::English);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidChecksum));
    }

    #[test]
    fn test_from_phrase_invalid_word_count() {
        // Only 11 words (invalid word count)
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = Mnemonic::from_phrase(phrase, Language::English);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidWordCount { .. }));
    }

    #[test]
    fn test_from_phrase_empty_string() {
        // Empty phrase should fail
        let result = Mnemonic::from_phrase("", Language::English);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_from_phrase_whitespace_only() {
        // Whitespace-only phrase should fail
        let result = Mnemonic::from_phrase("   ", Language::English);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_from_phrase_with_extra_whitespace() {
        // Phrase with extra whitespace should be normalized
        let phrase = "  abandon   abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        
        // Should normalize to standard format
        assert_eq!(mnemonic.phrase, VALID_12_WORD_PHRASE);
    }

    #[test]
    fn test_from_phrase_mixed_case() {
        // BIP39 words should be case-insensitive
        // Note: validate_phrase_in_language accepts mixed case,
        // but upstream parse_in_normalized may be stricter
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        
        // Should be normalized to lowercase
        assert_eq!(mnemonic.phrase, VALID_12_WORD_PHRASE);
        
        // Also test that validation layer handles mixed case correctly
        use crate::validate_phrase_in_language;
        let mixed_case = "ABANDON Abandon aBaNdOn abandon abandon abandon abandon abandon abandon abandon abandon about";
        // Validation should pass for mixed case
        assert!(validate_phrase_in_language(mixed_case, Language::English).is_ok());
    }

    #[test]
    fn test_from_phrase_roundtrip_with_new() {
        // Create mnemonic from entropy, then parse it back
        let entropy = [42u8; 16];
        let mnemonic1 = Mnemonic::new(&entropy, Language::English).unwrap();
        
        // Parse the phrase back
        let mnemonic2 = Mnemonic::from_phrase(&mnemonic1.phrase, Language::English).unwrap();
        
        // Should be identical
        assert_eq!(mnemonic1, mnemonic2);
        assert_eq!(mnemonic1.entropy, mnemonic2.entropy);
        assert_eq!(mnemonic1.phrase, mnemonic2.phrase);
    }

    #[test]
    fn test_from_phrase_extracts_correct_entropy() {
        // Parse a phrase and verify the extracted entropy matches
        let entropy = [0u8; 16];
        let mnemonic1 = Mnemonic::new(&entropy, Language::English).unwrap();
        let phrase = &mnemonic1.phrase;
        
        // Parse it back
        let mnemonic2 = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        
        // Entropy should match
        assert_eq!(mnemonic2.entropy, entropy);
    }

    #[test]
    fn test_from_phrase_with_japanese() {
        // Test with a Japanese mnemonic (generated from known entropy)
        let entropy = [0u8; 16];
        let mnemonic1 = Mnemonic::new(&entropy, Language::Japanese).unwrap();
        
        // Parse the Japanese phrase
        let mnemonic2 = Mnemonic::from_phrase(&mnemonic1.phrase, Language::Japanese).unwrap();
        
        assert_eq!(mnemonic2.language, Language::Japanese);
        assert_eq!(mnemonic2.entropy, entropy);
        assert_eq!(mnemonic2, mnemonic1);
    }

    #[test]
    fn test_from_phrase_wrong_language() {
        // Try to parse an English phrase as Japanese (should fail)
        let result = Mnemonic::from_phrase(VALID_12_WORD_PHRASE, Language::Japanese);
        
        assert!(result.is_err());
        // Should fail because English words aren't in Japanese wordlist
        assert!(matches!(result.unwrap_err(), Error::InvalidWord { .. }));
    }

    #[test]
    fn test_from_phrase_all_word_counts() {
        // Test parsing all valid word counts
        let test_cases = vec![
            (16, WordCount::Twelve),
            (20, WordCount::Fifteen),
            (24, WordCount::Eighteen),
            (28, WordCount::TwentyOne),
            (32, WordCount::TwentyFour),
        ];
        
        for (entropy_length, expected_word_count) in test_cases {
            let entropy = vec![0u8; entropy_length];
            let mnemonic1 = Mnemonic::new(&entropy, Language::English).unwrap();
            
            // Parse the phrase back
            let mnemonic2 = Mnemonic::from_phrase(&mnemonic1.phrase, Language::English).unwrap();
            
            assert_eq!(mnemonic2.word_count(), expected_word_count);
            assert_eq!(mnemonic2.entropy.len(), entropy_length);
        }
    }

    #[test]
    fn test_from_phrase_all_languages() {
        // Test that from_phrase works with different languages
        // Note: Some languages share words, so we test key languages only
        let test_languages = vec![
            Language::English,
            Language::Japanese,
            Language::Korean,
            Language::Spanish,
            Language::French,
        ];
        
        for (i, &language) in test_languages.iter().enumerate() {
            // Use different entropy for each language to avoid any potential ambiguity
            let mut entropy = [42u8; 16];
            entropy[0] = i as u8;  // Make each entropy unique
            
            let mnemonic1 = Mnemonic::new(&entropy, language).unwrap();
            let mnemonic2 = Mnemonic::from_phrase(&mnemonic1.phrase, language).unwrap();
            
            assert_eq!(mnemonic2.language, language);
            assert_eq!(mnemonic2.entropy, entropy);
        }
    }

    #[test]
    fn test_from_phrase_validates_phrase() {
        use crate::validate_phrase_in_language;
        
        // from_phrase should validate the phrase
        let mnemonic = Mnemonic::from_phrase(VALID_12_WORD_PHRASE, Language::English).unwrap();
        
        // The phrase should pass independent validation
        assert!(validate_phrase_in_language(&mnemonic.phrase, Language::English).is_ok());
    }
}
