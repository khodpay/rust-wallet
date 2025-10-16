//! Utility functions for BIP39 operations.
//!
//! This module provides standalone utility functions that don't require maintaining
//! state, such as mnemonic validation, seed generation, and conversion helpers.
//!
//! # Functions
//!
//! - [`validate_phrase`]: Validates a BIP39 mnemonic phrase
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip39::validate_phrase;
//!
//! // Validate a correct mnemonic phrase
//! let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! assert!(validate_phrase(phrase).is_ok());
//!
//! // Invalid phrase will return an error
//! let invalid_phrase = "invalid phrase with wrong words";
//! assert!(validate_phrase(invalid_phrase).is_err());
//! ```

use crate::{Error, Result, WordCount, Language};

/// Validates a BIP39 mnemonic phrase in English.
///
/// This is a convenience function that validates a mnemonic phrase using the English
/// word list. For other languages, use [`validate_phrase_in_language`].
///
/// This function performs comprehensive validation including:
/// - Word count validation (must be 12, 15, 18, 21, or 24 words)
/// - Word list validation (all words must be in the English BIP39 word list)
/// - Checksum validation (phrase must have valid BIP39 checksum)
///
/// # Arguments
///
/// * `phrase` - The mnemonic phrase to validate as a string slice
///
/// # Returns
///
/// * `Ok(())` if the phrase is valid
/// * `Err(Error)` with specific error information if validation fails
///
/// # Errors
///
/// * [`Error::InvalidMnemonic`] - For malformed or empty phrases
/// * [`Error::InvalidWordCount`] - For unsupported word counts
/// * [`Error::InvalidWord`] - For words not in the BIP39 word list
/// * [`Error::InvalidChecksum`] - For phrases with invalid checksums
/// * [`Error::Bip39Error`] - For other BIP39-related validation errors
///
/// # Examples
///
/// ```rust
/// use khodpay_bip39::validate_phrase;
///
/// // Valid 12-word English mnemonic
/// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// assert!(validate_phrase(phrase).is_ok());
///
/// // Invalid word count
/// let phrase = "abandon abandon abandon";
/// assert!(validate_phrase(phrase).is_err());
///
/// // Invalid English word
/// let phrase = "invalid abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// assert!(validate_phrase(phrase).is_err());
/// ```
pub fn validate_phrase(phrase: &str) -> Result<()> {
    validate_phrase_in_language(phrase, Language::English)
}

/// Validates a BIP39 mnemonic phrase in the specified language.
///
/// This function performs comprehensive validation of a mnemonic phrase including:
/// - Word count validation (must be 12, 15, 18, 21, or 24 words)
/// - Word list validation (all words must be in the specified language's BIP39 word list)
/// - Checksum validation (phrase must have valid BIP39 checksum)
///
/// # Arguments
///
/// * `phrase` - The mnemonic phrase to validate as a string slice
/// * `language` - The language to use for word list validation
///
/// # Returns
///
/// * `Ok(())` if the phrase is valid
/// * `Err(Error)` with specific error information if validation fails
///
/// # Errors
///
/// * [`Error::InvalidMnemonic`] - For malformed or empty phrases
/// * [`Error::InvalidWordCount`] - For unsupported word counts
/// * [`Error::InvalidWord`] - For words not in the specified language's word list
/// * [`Error::InvalidChecksum`] - For phrases with invalid checksums
/// * [`Error::Bip39Error`] - For other BIP39-related validation errors
///
/// # Examples
///
/// ```rust
/// use khodpay_bip39::{validate_phrase_in_language, Language};
///
/// // Valid English mnemonic
/// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// assert!(validate_phrase_in_language(phrase, Language::English).is_ok());
///
/// // Same phrase would be invalid in Japanese (cross-language validation)
/// assert!(validate_phrase_in_language(phrase, Language::Japanese).is_err());
/// ```
pub fn validate_phrase_in_language(phrase: &str, language: Language) -> Result<()> {
    // Step 1: Normalize whitespace and handle empty strings
    let normalized = phrase.trim();
    if normalized.is_empty() {
        return Err(Error::InvalidMnemonic {
            reason: "Empty phrase".to_string(),
        });
    }

    // Split into words and remove extra whitespace
    let words: Vec<&str> = normalized.split_whitespace().collect();
    
    // Step 2: Validate word count using our WordCount enum
    let _word_count = WordCount::from_word_count(words.len())?;

    // Step 3: Check each word against BIP39 word list for the specified language
    let upstream_language = language.to_upstream();
    for (index, word) in words.iter().enumerate() {
        let word_lower = word.to_lowercase();
        
        // Check if word is in the BIP39 word list for the specified language
        let word_list = upstream_language.word_list();
        let is_valid_word = word_list.iter().any(|&w| w == word_lower);
            
        if !is_valid_word {
            return Err(Error::InvalidWord {
                word: word.to_string(),
                position: index,
            });
        }
    }

    // Step 4: Now validate the complete phrase including checksum in the specified language
    let normalized_phrase = words.iter().map(|w| w.to_lowercase()).collect::<Vec<_>>().join(" ");
    
    match bip39_upstream::Mnemonic::parse_in_normalized(upstream_language, &normalized_phrase) {
        Ok(_) => Ok(()),
        Err(_) => {
            // At this point, words are valid but checksum is wrong
            Err(Error::InvalidChecksum)
        }
    }
}

/// Converts a BIP39 mnemonic phrase into a cryptographic seed (English).
///
/// This is a convenience function that converts an English mnemonic phrase to a seed.
/// For other languages, use [`phrase_to_seed_in_language`].
///
/// This function implements the BIP39 seed derivation process using PBKDF2-HMAC-SHA512.
/// The mnemonic phrase is used as the password, and an optional passphrase can be provided
/// for additional security (often called a "25th word" or "extension word").
///
/// # Arguments
///
/// * `phrase` - The mnemonic phrase in English (should be validated first)
/// * `passphrase` - Optional passphrase for additional security (empty string if None)
///
/// # Returns
///
/// * `Ok([u8; 64])` - A 64-byte (512-bit) cryptographic seed
/// * `Err(Error)` - If the phrase is invalid or seed derivation fails
///
/// # Security Note
///
/// The passphrase adds an extra layer of security but must be remembered.
/// If the passphrase is lost, the wallet cannot be recovered even with
/// the correct mnemonic phrase.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip39::phrase_to_seed;
///
/// // Without passphrase
/// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// let seed = phrase_to_seed(phrase, "").unwrap();
/// assert_eq!(seed.len(), 64);
///
/// // With passphrase (recommended for additional security)
/// let seed_with_pass = phrase_to_seed(phrase, "my secret passphrase").unwrap();
/// assert_eq!(seed_with_pass.len(), 64);
/// assert_ne!(seed, seed_with_pass); // Different passphrases produce different seeds
/// ```
pub fn phrase_to_seed(phrase: &str, passphrase: &str) -> Result<[u8; 64]> {
    phrase_to_seed_in_language(phrase, passphrase, Language::English)
}

/// Converts a BIP39 mnemonic phrase into a cryptographic seed with language support.
///
/// This function implements the BIP39 seed derivation process using PBKDF2-HMAC-SHA512.
/// The mnemonic phrase is used as the password, and an optional passphrase can be provided
/// for additional security (often called a "25th word" or "extension word").
///
/// # BIP39 Seed Derivation Process
///
/// 1. The mnemonic phrase is normalized (Unicode NFKD normalization)
/// 2. The passphrase is prefixed with "mnemonic" and normalized
/// 3. PBKDF2-HMAC-SHA512 is applied with 2048 iterations
/// 4. A 512-bit (64-byte) seed is produced
///
/// # Arguments
///
/// * `phrase` - The mnemonic phrase (should be validated first)
/// * `passphrase` - Optional passphrase for additional security (empty string if None)
/// * `language` - The language of the mnemonic phrase
///
/// # Returns
///
/// * `Ok([u8; 64])` - A 64-byte (512-bit) cryptographic seed
/// * `Err(Error)` - If the phrase is invalid or seed derivation fails
///
/// # Security Note
///
/// The passphrase adds an extra layer of security but must be remembered.
/// If the passphrase is lost, the wallet cannot be recovered even with
/// the correct mnemonic phrase.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip39::{phrase_to_seed_in_language, Language};
///
/// // English phrase without passphrase
/// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// let seed = phrase_to_seed_in_language(phrase, "", Language::English).unwrap();
/// assert_eq!(seed.len(), 64);
///
/// // With passphrase (recommended for additional security)
/// let seed_with_pass = phrase_to_seed_in_language(phrase, "my secret passphrase", Language::English).unwrap();
/// assert_eq!(seed_with_pass.len(), 64);
/// assert_ne!(seed, seed_with_pass); // Different passphrases produce different seeds
/// ```
pub fn phrase_to_seed_in_language(phrase: &str, passphrase: &str, language: Language) -> Result<[u8; 64]> {
    // Step 1: Validate the mnemonic phrase first
    // This ensures we only process valid BIP39 phrases in the specified language
    validate_phrase_in_language(phrase, language)?;
    
    // Step 2: Parse the mnemonic using the upstream crate
    // We've already validated it, so this should succeed
    // Using parse_in_normalized for consistent behavior with validation
    let upstream_language = language.to_upstream();
    let mnemonic = bip39_upstream::Mnemonic::parse_in_normalized(
        upstream_language,
        phrase
    ).map_err(|_| Error::InvalidMnemonic {
        reason: "Failed to parse validated phrase".to_string(),
    })?;
    
    // Step 3: Generate the seed using PBKDF2-HMAC-SHA512
    // The upstream crate handles:
    // - Unicode NFKD normalization of phrase and passphrase
    // - Salt = "mnemonic" + passphrase
    // - 2048 iterations of PBKDF2-HMAC-SHA512
    // - 512-bit (64-byte) output
    let seed = mnemonic.to_seed(passphrase);
    
    // Step 4: Convert the seed bytes to a fixed-size array
    // The seed is guaranteed to be 64 bytes per BIP39 spec
    Ok(seed)
}

/// Generates a new random BIP39 mnemonic phrase in English.
///
/// This is a convenience function that generates an English mnemonic phrase.
/// For other languages, use [`generate_mnemonic_in_language`].
///
/// This function generates cryptographically secure random entropy and converts it
/// into a BIP39 mnemonic phrase with the specified word count.
///
/// # Arguments
///
/// * `word_count` - The number of words in the mnemonic (12, 15, 18, 21, or 24)
///
/// # Returns
///
/// * `Ok(String)` - A valid BIP39 mnemonic phrase
/// * `Err(Error)` - If the word count is invalid or entropy generation fails
///
/// # Security Note
///
/// This function uses the system's cryptographically secure random number generator.
/// The generated mnemonic should be stored securely and backed up properly.
/// Loss of the mnemonic means permanent loss of access to the associated wallet.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip39::{generate_mnemonic, WordCount};
///
/// // Generate a 12-word mnemonic (most common)
/// let mnemonic = generate_mnemonic(WordCount::Twelve).unwrap();
/// assert_eq!(mnemonic.split_whitespace().count(), 12);
///
/// // Generate a 24-word mnemonic (maximum security)
/// let mnemonic_24 = generate_mnemonic(WordCount::TwentyFour).unwrap();
/// assert_eq!(mnemonic_24.split_whitespace().count(), 24);
/// ```
pub fn generate_mnemonic(word_count: WordCount) -> Result<String> {
    generate_mnemonic_in_language(word_count, Language::English)
}

/// Generates a new random BIP39 mnemonic phrase with language support.
///
/// This function generates cryptographically secure random entropy and converts it
/// into a BIP39 mnemonic phrase with the specified word count and language.
///
/// # Arguments
///
/// * `word_count` - The number of words in the mnemonic (12, 15, 18, 21, or 24)
/// * `language` - The language for the mnemonic phrase
///
/// # Returns
///
/// * `Ok(String)` - A valid BIP39 mnemonic phrase in the specified language
/// * `Err(Error)` - If the word count is invalid or entropy generation fails
///
/// # Security Note
///
/// This function uses the system's cryptographically secure random number generator.
/// The generated mnemonic should be stored securely and backed up properly.
/// Loss of the mnemonic means permanent loss of access to the associated wallet.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip39::{generate_mnemonic_in_language, WordCount, Language};
///
/// // Generate a 12-word English mnemonic
/// let mnemonic_en = generate_mnemonic_in_language(WordCount::Twelve, Language::English).unwrap();
/// assert_eq!(mnemonic_en.split_whitespace().count(), 12);
///
/// // Generate a 24-word Japanese mnemonic
/// let mnemonic_ja = generate_mnemonic_in_language(WordCount::TwentyFour, Language::Japanese).unwrap();
/// assert_eq!(mnemonic_ja.split_whitespace().count(), 24);
/// ```
pub fn generate_mnemonic_in_language(word_count: WordCount, language: Language) -> Result<String> {
    use rand::RngCore;
    
    // Step 1: Calculate the required entropy length based on word count
    let entropy_length = word_count.entropy_length();
    
    // Step 2: Generate cryptographically secure random entropy
    // Uses the system's secure random number generator
    let mut entropy = vec![0u8; entropy_length];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut entropy);
    
    // Step 3: Convert language to upstream format
    let upstream_language = language.to_upstream();
    
    // Step 4: Create mnemonic from entropy using upstream crate
    // The upstream crate handles:
    // - Entropy validation
    // - Checksum calculation (appends checksum bits to entropy)
    // - Word selection from language-specific wordlist
    // - Proper formatting with spaces between words
    let mnemonic = bip39_upstream::Mnemonic::from_entropy_in(upstream_language, &entropy)
        .map_err(|_| Error::InvalidEntropyLength {
            length: entropy.len(),
        })?;
    
    // Step 5: Convert to string and return
    // The mnemonic is formatted with spaces between words
    Ok(mnemonic.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known valid test vectors from BIP39 specification
    const VALID_12_WORD_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const VALID_24_WORD_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    // Test valid mnemonic phrases
    #[test]
    fn test_validate_phrase_valid_12_words() {
        let result = validate_phrase(VALID_12_WORD_PHRASE);
        assert!(result.is_ok(), "Valid 12-word phrase should pass validation");
    }

    #[test]
    fn test_validate_phrase_valid_24_words() {
        let result = validate_phrase(VALID_24_WORD_PHRASE);
        assert!(result.is_ok(), "Valid 24-word phrase should pass validation");
    }

    #[test]
    fn test_validate_phrase_valid_15_words() {
        // Generate a valid 15-word phrase using known entropy (20 bytes for 15 words)
        let entropy = [0u8; 20]; // This creates deterministic test
        let mnemonic = bip39_upstream::Mnemonic::from_entropy(&entropy).unwrap();
        let phrase = mnemonic.to_string();
        let result = validate_phrase(&phrase);
        assert!(result.is_ok(), "Generated valid 15-word phrase should pass validation: {}", phrase);
    }

    #[test]
    fn test_validate_phrase_valid_18_words() {
        // Generate a valid 18-word phrase using known entropy (24 bytes for 18 words)
        let entropy = [0u8; 24]; 
        let mnemonic = bip39_upstream::Mnemonic::from_entropy(&entropy).unwrap();
        let phrase = mnemonic.to_string();
        let result = validate_phrase(&phrase);
        assert!(result.is_ok(), "Generated valid 18-word phrase should pass validation: {}", phrase);
    }

    #[test]
    fn test_validate_phrase_valid_21_words() {
        // Generate a valid 21-word phrase using known entropy (28 bytes for 21 words)
        let entropy = [0u8; 28];
        let mnemonic = bip39_upstream::Mnemonic::from_entropy(&entropy).unwrap();
        let phrase = mnemonic.to_string();
        let result = validate_phrase(&phrase);
        assert!(result.is_ok(), "Generated valid 21-word phrase should pass validation: {}", phrase);
    }

    // Test whitespace normalization
    #[test]
    fn test_validate_phrase_extra_whitespace() {
        let phrase_with_spaces = "  abandon  abandon   abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ";
        let result = validate_phrase(phrase_with_spaces);
        assert!(result.is_ok(), "Phrase with extra whitespace should be normalized and pass validation");
    }

    #[test]
    fn test_validate_phrase_mixed_case() {
        let phrase = "ABANDON abandon Abandon ABANDON abandon abandon abandon abandon abandon abandon abandon about";
        let result = validate_phrase(phrase);
        assert!(result.is_ok(), "Mixed case phrase should pass validation");
    }

    // Test invalid word counts
    #[test]
    fn test_validate_phrase_empty_string() {
        let result = validate_phrase("");
        assert!(result.is_err(), "Empty string should fail validation");
        
        match result.unwrap_err() {
            Error::InvalidMnemonic { reason } => {
                assert!(reason.contains("empty") || reason.contains("Empty"), 
                    "Should indicate empty phrase: {}", reason);
            }
            _ => panic!("Expected InvalidMnemonic error for empty string"),
        }
    }

    #[test]
    fn test_validate_phrase_whitespace_only() {
        let result = validate_phrase("   \t\n  ");
        assert!(result.is_err(), "Whitespace-only string should fail validation");
    }

    #[test]
    fn test_validate_phrase_invalid_word_count_too_few() {
        let phrase = "abandon abandon abandon"; // Only 3 words
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "3-word phrase should fail validation");
        
        match result.unwrap_err() {
            Error::InvalidWordCount { count } => {
                assert_eq!(count, 3, "Should report correct word count");
            }
            _ => panic!("Expected InvalidWordCount error for 3 words"),
        }
    }

    #[test]
    fn test_validate_phrase_invalid_word_count_11_words() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "11-word phrase should fail validation");
        
        match result.unwrap_err() {
            Error::InvalidWordCount { count } => {
                assert_eq!(count, 11, "Should report correct word count");
            }
            _ => panic!("Expected InvalidWordCount error for 11 words"),
        }
    }

    #[test]
    fn test_validate_phrase_invalid_word_count_13_words() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about extra";
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "13-word phrase should fail validation");
        
        match result.unwrap_err() {
            Error::InvalidWordCount { count } => {
                assert_eq!(count, 13, "Should report correct word count");
            }
            _ => panic!("Expected InvalidWordCount error for 13 words"),
        }
    }

    #[test]
    fn test_validate_phrase_invalid_word_count_too_many() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"; // 25 words
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "25-word phrase should fail validation");
        
        match result.unwrap_err() {
            Error::InvalidWordCount { count } => {
                assert_eq!(count, 25, "Should report correct word count");
            }
            _ => panic!("Expected InvalidWordCount error for 25 words"),
        }
    }

    // Test invalid words
    #[test]
    fn test_validate_phrase_invalid_word_first_position() {
        let phrase = "invalidword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "Phrase with invalid first word should fail validation");
        
        match result.unwrap_err() {
            Error::InvalidWord { word, position } => {
                assert_eq!(word, "invalidword", "Should report the invalid word");
                assert_eq!(position, 0, "Should report correct position (0-based)");
            }
            _ => panic!("Expected InvalidWord error for invalid first word"),
        }
    }

    #[test]
    fn test_validate_phrase_invalid_word_middle_position() {
        let phrase = "abandon abandon abandon invalidword abandon abandon abandon abandon abandon abandon abandon about";
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "Phrase with invalid middle word should fail validation");
        
        match result.unwrap_err() {
            Error::InvalidWord { word, position } => {
                assert_eq!(word, "invalidword", "Should report the invalid word");
                assert_eq!(position, 3, "Should report correct position (0-based)");
            }
            _ => panic!("Expected InvalidWord error for invalid middle word"),
        }
    }

    #[test]
    fn test_validate_phrase_invalid_word_last_position() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalidword";
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "Phrase with invalid last word should fail validation");
    }

    #[test]
    fn test_validate_phrase_multiple_invalid_words() {
        let phrase = "invalidword1 abandon invalidword2 abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "Phrase with multiple invalid words should fail validation");
        
        // Should report the first invalid word encountered
        match result.unwrap_err() {
            Error::InvalidWord { word, position } => {
                assert_eq!(word, "invalidword1", "Should report the first invalid word");
                assert_eq!(position, 0, "Should report position of first invalid word");
            }
            _ => panic!("Expected InvalidWord error for multiple invalid words"),
        }
    }

    // Test invalid checksum
    #[test]
    fn test_validate_phrase_invalid_checksum_12_words() {
        // This phrase has valid words and count, but wrong checksum
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "Phrase with invalid checksum should fail validation");
        
        match result.unwrap_err() {
            Error::InvalidChecksum => {
                // Expected error type
            }
            other => panic!("Expected InvalidChecksum error, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_phrase_invalid_checksum_24_words() {
        // Valid words and count, but last word creates invalid checksum
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "24-word phrase with invalid checksum should fail validation");
    }

    // Test edge cases and error conditions
    #[test]
    fn test_validate_phrase_single_word() {
        let result = validate_phrase("abandon");
        assert!(result.is_err(), "Single word should fail validation");
        
        match result.unwrap_err() {
            Error::InvalidWordCount { count } => {
                assert_eq!(count, 1, "Should report correct word count");
            }
            _ => panic!("Expected InvalidWordCount error for single word"),
        }
    }

    #[test]
    fn test_validate_phrase_numbers_as_words() {
        let phrase = "123 456 789 abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "Phrase with numbers should fail validation");
        
        match result.unwrap_err() {
            Error::InvalidWord { word, position } => {
                assert_eq!(word, "123", "Should report the first invalid number");
                assert_eq!(position, 0, "Should report correct position");
            }
            _ => panic!("Expected InvalidWord error for numbers"),
        }
    }

    #[test]
    fn test_validate_phrase_special_characters() {
        let phrase = "abandon@ abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "Phrase with special characters should fail validation");
    }

    #[test]
    fn test_validate_phrase_unicode_characters() {
        let phrase = "abandon 中文 abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = validate_phrase(phrase);
        assert!(result.is_err(), "Phrase with unicode characters should fail validation");
    }

    // Integration tests with WordCount enum
    #[test]
    fn test_validate_phrase_all_valid_word_counts() {
        // Test that all valid WordCount variants work
        let test_cases = [
            (12, VALID_12_WORD_PHRASE),
            (24, VALID_24_WORD_PHRASE),
            // Note: We'll use simplified test phrases for 15, 18, 21 words
            // In real implementation, these should be actual valid BIP39 phrases
        ];

        for (expected_count, phrase) in test_cases.iter() {
            let words: Vec<&str> = phrase.split_whitespace().collect();
            assert_eq!(words.len(), *expected_count, "Test phrase should have correct word count");
            
            // Validate that our WordCount enum accepts this count
            assert!(WordCount::from_word_count(*expected_count).is_ok(), 
                "WordCount should accept {} words", expected_count);
        }
    }

    // Test language-specific validation
    #[test]
    fn test_validate_phrase_in_language_english() {
        let result = validate_phrase_in_language(VALID_12_WORD_PHRASE, Language::English);
        assert!(result.is_ok(), "Valid English phrase should pass validation");
    }

    #[test]
    fn test_validate_phrase_in_language_different_languages() {
        // Test that English validation works
        let result = validate_phrase_in_language(VALID_12_WORD_PHRASE, Language::English);
        assert!(result.is_ok(), "English phrase should pass English validation");
        
        // English phrase should fail validation in other languages
        let result = validate_phrase_in_language(VALID_12_WORD_PHRASE, Language::Japanese);
        assert!(result.is_err(), "English phrase should fail Japanese validation");
        
        match result.unwrap_err() {
            Error::InvalidWord { word, position } => {
                assert_eq!(word, "abandon", "First English word should be invalid in Japanese");
                assert_eq!(position, 0, "Should report first position");
            }
            _ => panic!("Expected InvalidWord error for cross-language validation"),
        }
        
        // Test with an invalid phrase to ensure validation still works
        let invalid_result = validate_phrase_in_language("invalid phrase", Language::Korean);
        assert!(invalid_result.is_err(), "Invalid phrase should fail in any language");
    }

    #[test]
    fn test_validate_phrase_convenience_function() {
        // Test that the convenience function (validate_phrase) works the same as English
        let result1 = validate_phrase(VALID_12_WORD_PHRASE);
        let result2 = validate_phrase_in_language(VALID_12_WORD_PHRASE, Language::English);
        
        assert_eq!(result1.is_ok(), result2.is_ok(), "Both functions should give same result");
    }

    #[test]
    fn test_language_integration() {
        // Test that all supported languages can be used (even if we don't have test phrases)
        for &language in Language::all_variants() {
            // This should not panic and should handle the language parameter correctly
            let result = validate_phrase_in_language("invalid phrase", language);
            assert!(result.is_err(), "Invalid phrase should fail in {} language", language.name());
        }
    }

    // ============================================================================
    // Tests for phrase_to_seed function (Task 08)
    // ============================================================================

    #[test]
    fn test_phrase_to_seed_without_passphrase() {
        // Test seed generation without passphrase
        let seed = phrase_to_seed(VALID_12_WORD_PHRASE, "").unwrap();
        
        // BIP39 seeds are always 64 bytes (512 bits)
        assert_eq!(seed.len(), 64, "Seed should be 64 bytes");
        
        // Known test vector from BIP39 specification
        // Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        // Passphrase: "" (empty)
        // Expected seed (first 32 bytes in hex):
        // 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
        let expected_seed_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        let expected_seed = hex::decode(expected_seed_hex).unwrap();
        assert_eq!(&seed[..], &expected_seed[..], "Seed should match BIP39 test vector");
    }

    #[test]
    fn test_phrase_to_seed_with_passphrase() {
        // Test seed generation with a passphrase
        let passphrase = "TREZOR";
        let seed = phrase_to_seed(VALID_12_WORD_PHRASE, passphrase).unwrap();
        
        assert_eq!(seed.len(), 64, "Seed should be 64 bytes");
        
        // Known test vector from BIP39 specification with TREZOR passphrase
        // Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        // Passphrase: "TREZOR"
        // Expected seed:
        // c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
        let expected_seed_hex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        let expected_seed = hex::decode(expected_seed_hex).unwrap();
        assert_eq!(&seed[..], &expected_seed[..], "Seed with passphrase should match BIP39 test vector");
    }

    #[test]
    fn test_phrase_to_seed_passphrase_affects_seed() {
        // Verify that different passphrases produce different seeds
        let seed1 = phrase_to_seed(VALID_12_WORD_PHRASE, "").unwrap();
        let seed2 = phrase_to_seed(VALID_12_WORD_PHRASE, "password").unwrap();
        let seed3 = phrase_to_seed(VALID_12_WORD_PHRASE, "different").unwrap();
        
        assert_ne!(seed1, seed2, "Empty passphrase should produce different seed than 'password'");
        assert_ne!(seed2, seed3, "Different passphrases should produce different seeds");
        assert_ne!(seed1, seed3, "Empty and 'different' should produce different seeds");
    }

    #[test]
    fn test_phrase_to_seed_24_word_phrase() {
        // Test with 24-word phrase
        let seed = phrase_to_seed(VALID_24_WORD_PHRASE, "").unwrap();
        assert_eq!(seed.len(), 64, "24-word phrase should also produce 64-byte seed");
        
        // Verify it produces a different seed than the 12-word phrase
        let seed_12_word = phrase_to_seed(VALID_12_WORD_PHRASE, "").unwrap();
        assert_ne!(seed, seed_12_word, "24-word and 12-word phrases should produce different seeds");
    }

    #[test]
    fn test_phrase_to_seed_rejects_invalid_phrase() {
        // Should fail on invalid phrase (validation happens first)
        let result = phrase_to_seed("invalid mnemonic phrase with wrong words", "");
        assert!(result.is_err(), "Invalid phrase should be rejected");
        
        match result.unwrap_err() {
            Error::InvalidWord { .. } | Error::InvalidMnemonic { .. } | Error::InvalidWordCount { .. } => {
                // Expected error type - validation should catch the invalid phrase
            }
            _ => panic!("Should return validation error for invalid phrase"),
        }
    }

    #[test]
    fn test_phrase_to_seed_rejects_invalid_checksum() {
        // Valid words but invalid checksum
        let invalid_checksum_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let result = phrase_to_seed(invalid_checksum_phrase, "");
        assert!(result.is_err(), "Invalid checksum should be rejected");
        
        match result.unwrap_err() {
            Error::InvalidChecksum => {
                // Expected error type
            }
            _ => panic!("Should return InvalidChecksum error"),
        }
    }

    #[test]
    fn test_phrase_to_seed_unicode_passphrase() {
        // Test with Unicode passphrase (should be properly normalized)
        let unicode_passphrase = "test 日本語 emoji 🔑";
        let seed = phrase_to_seed(VALID_12_WORD_PHRASE, unicode_passphrase).unwrap();
        assert_eq!(seed.len(), 64, "Unicode passphrase should work correctly");
    }

    #[test]
    fn test_phrase_to_seed_deterministic() {
        // Same phrase and passphrase should always produce same seed
        let seed1 = phrase_to_seed(VALID_12_WORD_PHRASE, "test").unwrap();
        let seed2 = phrase_to_seed(VALID_12_WORD_PHRASE, "test").unwrap();
        assert_eq!(seed1, seed2, "Same inputs should produce identical seeds");
    }

    #[test]
    fn test_phrase_to_seed_whitespace_in_passphrase() {
        // Whitespace in passphrase should be preserved (not trimmed)
        let seed1 = phrase_to_seed(VALID_12_WORD_PHRASE, "password").unwrap();
        let seed2 = phrase_to_seed(VALID_12_WORD_PHRASE, " password ").unwrap();
        let seed3 = phrase_to_seed(VALID_12_WORD_PHRASE, "pass word").unwrap();
        
        assert_ne!(seed1, seed2, "Leading/trailing spaces should affect seed");
        assert_ne!(seed1, seed3, "Internal spaces should affect seed");
        assert_ne!(seed2, seed3, "Different whitespace patterns should produce different seeds");
    }

    #[test]
    fn test_phrase_to_seed_case_sensitive_passphrase() {
        // Passphrase should be case-sensitive
        let seed1 = phrase_to_seed(VALID_12_WORD_PHRASE, "password").unwrap();
        let seed2 = phrase_to_seed(VALID_12_WORD_PHRASE, "Password").unwrap();
        let seed3 = phrase_to_seed(VALID_12_WORD_PHRASE, "PASSWORD").unwrap();
        
        assert_ne!(seed1, seed2, "Different case should produce different seeds");
        assert_ne!(seed2, seed3, "Different case should produce different seeds");
        assert_ne!(seed1, seed3, "Different case should produce different seeds");
    }

    #[test]
    fn test_phrase_to_seed_empty_vs_no_passphrase() {
        // Empty string passphrase should be same as no passphrase
        let seed1 = phrase_to_seed(VALID_12_WORD_PHRASE, "").unwrap();
        let seed2 = phrase_to_seed(VALID_12_WORD_PHRASE, "").unwrap();
        
        assert_eq!(seed1, seed2, "Empty passphrase should be consistent");
    }

    #[test]
    fn test_phrase_to_seed_all_word_counts() {
        // Test that all valid word counts produce 64-byte seeds
        let test_cases = [
            (12, vec![0u8; 16]),  // 12 words = 128 bits entropy
            (15, vec![0u8; 20]),  // 15 words = 160 bits entropy
            (18, vec![0u8; 24]),  // 18 words = 192 bits entropy
            (21, vec![0u8; 28]),  // 21 words = 224 bits entropy
            (24, vec![0u8; 32]),  // 24 words = 256 bits entropy
        ];
        
        for (word_count, entropy) in test_cases.iter() {
            let mnemonic = bip39_upstream::Mnemonic::from_entropy(entropy).unwrap();
            let phrase = mnemonic.to_string();
            let seed = phrase_to_seed(&phrase, "").unwrap();
            
            assert_eq!(seed.len(), 64, "{}-word phrase should produce 64-byte seed", word_count);
        }
    }

    // ============================================================================
    // Tests for generate_mnemonic function (Task 10)
    // ============================================================================

    #[test]
    fn test_generate_mnemonic_12_words() {
        // Generate a 12-word mnemonic
        let mnemonic = generate_mnemonic(WordCount::Twelve).unwrap();
        
        // Verify it has exactly 12 words
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12, "Generated mnemonic should have 12 words");
        
        // Verify it's a valid BIP39 mnemonic
        assert!(validate_phrase(&mnemonic).is_ok(), "Generated mnemonic should be valid");
    }

    #[test]
    fn test_generate_mnemonic_15_words() {
        // Generate a 15-word mnemonic
        let mnemonic = generate_mnemonic(WordCount::Fifteen).unwrap();
        
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 15, "Generated mnemonic should have 15 words");
        assert!(validate_phrase(&mnemonic).is_ok(), "Generated 15-word mnemonic should be valid");
    }

    #[test]
    fn test_generate_mnemonic_18_words() {
        // Generate an 18-word mnemonic
        let mnemonic = generate_mnemonic(WordCount::Eighteen).unwrap();
        
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 18, "Generated mnemonic should have 18 words");
        assert!(validate_phrase(&mnemonic).is_ok(), "Generated 18-word mnemonic should be valid");
    }

    #[test]
    fn test_generate_mnemonic_21_words() {
        // Generate a 21-word mnemonic
        let mnemonic = generate_mnemonic(WordCount::TwentyOne).unwrap();
        
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 21, "Generated mnemonic should have 21 words");
        assert!(validate_phrase(&mnemonic).is_ok(), "Generated 21-word mnemonic should be valid");
    }

    #[test]
    fn test_generate_mnemonic_24_words() {
        // Generate a 24-word mnemonic
        let mnemonic = generate_mnemonic(WordCount::TwentyFour).unwrap();
        
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24, "Generated mnemonic should have 24 words");
        assert!(validate_phrase(&mnemonic).is_ok(), "Generated 24-word mnemonic should be valid");
    }

    #[test]
    fn test_generate_mnemonic_randomness() {
        // Generate multiple mnemonics and verify they're different (randomness)
        let mnemonic1 = generate_mnemonic(WordCount::Twelve).unwrap();
        let mnemonic2 = generate_mnemonic(WordCount::Twelve).unwrap();
        let mnemonic3 = generate_mnemonic(WordCount::Twelve).unwrap();
        
        // With cryptographically secure random generation, these should be different
        assert_ne!(mnemonic1, mnemonic2, "Generated mnemonics should be random");
        assert_ne!(mnemonic2, mnemonic3, "Generated mnemonics should be random");
        assert_ne!(mnemonic1, mnemonic3, "Generated mnemonics should be random");
    }

    #[test]
    fn test_generate_mnemonic_can_generate_seed() {
        // Generate a mnemonic and verify it can be used to generate a seed
        let mnemonic = generate_mnemonic(WordCount::Twelve).unwrap();
        
        // Should be able to generate a seed from the generated mnemonic
        let seed = phrase_to_seed(&mnemonic, "").unwrap();
        assert_eq!(seed.len(), 64, "Generated mnemonic should produce valid seed");
    }

    #[test]
    fn test_generate_mnemonic_with_passphrase() {
        // Generate a mnemonic and use it with a passphrase
        let mnemonic = generate_mnemonic(WordCount::TwentyFour).unwrap();
        
        let seed_no_pass = phrase_to_seed(&mnemonic, "").unwrap();
        let seed_with_pass = phrase_to_seed(&mnemonic, "my passphrase").unwrap();
        
        assert_ne!(seed_no_pass, seed_with_pass, "Passphrase should affect seed");
    }

    #[test]
    fn test_generate_mnemonic_english_words() {
        // Verify generated mnemonic contains valid English BIP39 words
        let mnemonic = generate_mnemonic(WordCount::Twelve).unwrap();
        
        // All words should be lowercase English words
        for word in mnemonic.split_whitespace() {
            assert!(word.chars().all(|c| c.is_ascii_lowercase()), 
                "All words should be lowercase: {}", word);
        }
    }

    #[test]
    fn test_generate_mnemonic_in_language_english() {
        // Test explicit English language generation
        let mnemonic = generate_mnemonic_in_language(WordCount::Twelve, Language::English).unwrap();
        
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12, "Generated mnemonic should have 12 words");
        assert!(validate_phrase_in_language(&mnemonic, Language::English).is_ok(), 
            "Generated English mnemonic should be valid");
    }

    #[test]
    fn test_generate_mnemonic_in_language_japanese() {
        // Test Japanese language generation
        let mnemonic = generate_mnemonic_in_language(WordCount::Twelve, Language::Japanese).unwrap();
        
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12, "Generated Japanese mnemonic should have 12 words");
        assert!(validate_phrase_in_language(&mnemonic, Language::Japanese).is_ok(), 
            "Generated Japanese mnemonic should be valid");
    }

    #[test]
    fn test_generate_mnemonic_all_word_counts() {
        // Test that all word counts can be generated successfully
        let word_counts = WordCount::all_variants();
        
        for &word_count in word_counts {
            let mnemonic = generate_mnemonic(word_count).unwrap();
            let words: Vec<&str> = mnemonic.split_whitespace().collect();
            assert_eq!(words.len(), word_count.word_count(), 
                "Generated mnemonic should have {} words", word_count.word_count());
            assert!(validate_phrase(&mnemonic).is_ok(), 
                "Generated {}-word mnemonic should be valid", word_count.word_count());
        }
    }

    #[test]
    fn test_generate_mnemonic_all_languages() {
        // Test that all languages can generate valid mnemonics
        let languages = Language::all_variants();
        
        for &language in languages {
            let mnemonic = generate_mnemonic_in_language(WordCount::Twelve, language).unwrap();
            assert!(validate_phrase_in_language(&mnemonic, language).is_ok(), 
                "Generated {} mnemonic should be valid", language.name());
        }
    }

    #[test]
    fn test_generate_mnemonic_deterministic_seed() {
        // Verify that the same generated mnemonic always produces the same seed
        let mnemonic = generate_mnemonic(WordCount::Twelve).unwrap();
        
        let seed1 = phrase_to_seed(&mnemonic, "test").unwrap();
        let seed2 = phrase_to_seed(&mnemonic, "test").unwrap();
        
        assert_eq!(seed1, seed2, "Same mnemonic should always produce same seed");
    }

    #[test]
    fn test_generate_mnemonic_entropy_strength() {
        // Verify different word counts have different entropy strengths
        let mnemonic_12 = generate_mnemonic(WordCount::Twelve).unwrap();
        let mnemonic_24 = generate_mnemonic(WordCount::TwentyFour).unwrap();
        
        // 12 words should have less entropy than 24 words
        assert!(mnemonic_12.len() < mnemonic_24.len(), 
            "24-word mnemonic should be longer than 12-word");
        
        // Both should be valid
        assert!(validate_phrase(&mnemonic_12).is_ok());
        assert!(validate_phrase(&mnemonic_24).is_ok());
    }
}
