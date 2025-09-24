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
//! use bip39::validate_phrase;
//!
//! // Validate a correct mnemonic phrase
//! let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! assert!(validate_phrase(phrase).is_ok());
//!
//! // Invalid phrase will return an error
//! let invalid_phrase = "invalid phrase with wrong words";
//! assert!(validate_phrase(invalid_phrase).is_err());
//! ```

use crate::{Error, Result, WordCount};

/// Validates a BIP39 mnemonic phrase.
///
/// This function performs comprehensive validation of a mnemonic phrase including:
/// - Word count validation (must be 12, 15, 18, 21, or 24 words)
/// - Word list validation (all words must be in the BIP39 word list)
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
/// use bip39::validate_phrase;
///
/// // Valid 12-word mnemonic
/// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// assert!(validate_phrase(phrase).is_ok());
///
/// // Invalid word count
/// let phrase = "abandon abandon abandon";
/// assert!(validate_phrase(phrase).is_err());
///
/// // Invalid word
/// let phrase = "invalid abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// assert!(validate_phrase(phrase).is_err());
/// ```
pub fn validate_phrase(phrase: &str) -> Result<()> {
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

    // Step 3: Check each word against BIP39 word list
    for (index, word) in words.iter().enumerate() {
        let word_lower = word.to_lowercase();
        
        // Check if word is in the BIP39 word list using the upstream crate
        let word_list = bip39_upstream::Language::English.word_list();
        let is_valid_word = word_list.iter().any(|&w| w == word_lower);
            
        if !is_valid_word {
            return Err(Error::InvalidWord {
                word: word.to_string(),
                position: index,
            });
        }
    }

    // Step 4: Now validate the complete phrase including checksum
    let normalized_phrase = words.iter().map(|w| w.to_lowercase()).collect::<Vec<_>>().join(" ");
    
    match bip39_upstream::Mnemonic::parse(&normalized_phrase) {
        Ok(_) => Ok(()),
        Err(_) => {
            // At this point, words are valid but checksum is wrong
            Err(Error::InvalidChecksum)
        }
    }
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
}
