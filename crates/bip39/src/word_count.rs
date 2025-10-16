//! BIP39 word count definitions and conversions.
//!
//! This module provides the [`WordCount`] enum that represents all valid BIP39 word counts
//! and their relationships to entropy lengths and checksum bits.
//!
//! # BIP39 Word Count Specifications
//!
//! | Word Count | Entropy Bits | Entropy Bytes | Checksum Bits | Total Bits |
//! |------------|--------------|---------------|---------------|------------|
//! | 12 words   | 128 bits     | 16 bytes      | 4 bits        | 132 bits   |
//! | 15 words   | 160 bits     | 20 bytes      | 5 bits        | 165 bits   |
//! | 18 words   | 192 bits     | 24 bytes      | 6 bits        | 198 bits   |
//! | 21 words   | 224 bits     | 28 bytes      | 7 bits        | 231 bits   |
//! | 24 words   | 256 bits     | 32 bytes      | 8 bits        | 264 bits   |
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip39::WordCount;
//!
//! // Get word count and entropy length
//! let wc = WordCount::Twelve;
//! assert_eq!(wc.word_count(), 12);
//! assert_eq!(wc.entropy_length(), 16);
//!
//! // Create from values
//! let wc = WordCount::from_word_count(24).unwrap();
//! assert_eq!(wc, WordCount::TwentyFour);
//! ```

use crate::{Error, Result};

/// Represents the valid word counts for BIP39 mnemonics.
///
/// BIP39 supports exactly 5 different word counts, each corresponding to
/// a specific entropy length and checksum size. This enum provides type-safe
/// representation and conversion methods.
///
/// # Variants
///
/// - [`Twelve`]: 12 words from 128-bit (16-byte) entropy
/// - [`Fifteen`]: 15 words from 160-bit (20-byte) entropy  
/// - [`Eighteen`]: 18 words from 192-bit (24-byte) entropy
/// - [`TwentyOne`]: 21 words from 224-bit (28-byte) entropy
/// - [`TwentyFour`]: 24 words from 256-bit (32-byte) entropy
///
/// [`Twelve`]: WordCount::Twelve
/// [`Fifteen`]: WordCount::Fifteen
/// [`Eighteen`]: WordCount::Eighteen
/// [`TwentyOne`]: WordCount::TwentyOne
/// [`TwentyFour`]: WordCount::TwentyFour
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WordCount {
    /// 12-word mnemonic from 128-bit (16-byte) entropy with 4-bit checksum.
    ///
    /// This is the most common word count, providing adequate security
    /// while being relatively easy to manage and remember.
    ///
    /// # Example
    /// ```rust
    /// # use khodpay_bip39::WordCount;
    /// let wc = WordCount::Twelve;
    /// assert_eq!(wc.word_count(), 12);
    /// assert_eq!(wc.entropy_length(), 16);
    /// assert_eq!(wc.checksum_bits(), 4);
    /// ```
    Twelve,

    /// 15-word mnemonic from 160-bit (20-byte) entropy with 5-bit checksum.
    ///
    /// Less commonly used but provides additional security over 12-word mnemonics.
    Fifteen,

    /// 18-word mnemonic from 192-bit (24-byte) entropy with 6-bit checksum.
    ///
    /// Provides strong security while remaining manageable for most users.
    Eighteen,

    /// 21-word mnemonic from 224-bit (28-byte) entropy with 7-bit checksum.
    ///
    /// High security option, less commonly used due to length.
    TwentyOne,

    /// 24-word mnemonic from 256-bit (32-byte) entropy with 8-bit checksum.
    ///
    /// Maximum security BIP39 mnemonic, commonly used for high-value wallets.
    ///
    /// # Example
    /// ```rust
    /// # use khodpay_bip39::WordCount;
    /// let wc = WordCount::TwentyFour;
    /// assert_eq!(wc.word_count(), 24);
    /// assert_eq!(wc.entropy_length(), 32);
    /// assert_eq!(wc.checksum_bits(), 8);
    /// ```
    TwentyFour,
}

impl WordCount {
    /// Returns the number of words for this word count.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use khodpay_bip39::WordCount;
    /// assert_eq!(WordCount::Twelve.word_count(), 12);
    /// assert_eq!(WordCount::TwentyFour.word_count(), 24);
    /// ```
    pub const fn word_count(&self) -> usize {
        match self {
            WordCount::Twelve => 12,
            WordCount::Fifteen => 15,
            WordCount::Eighteen => 18,
            WordCount::TwentyOne => 21,
            WordCount::TwentyFour => 24,
        }
    }

    /// Returns the entropy length in bytes for this word count.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use khodpay_bip39::WordCount;
    /// assert_eq!(WordCount::Twelve.entropy_length(), 16);
    /// assert_eq!(WordCount::TwentyFour.entropy_length(), 32);
    /// ```
    pub const fn entropy_length(&self) -> usize {
        match self {
            WordCount::Twelve => 16,     // 128 bits
            WordCount::Fifteen => 20,    // 160 bits
            WordCount::Eighteen => 24,   // 192 bits
            WordCount::TwentyOne => 28,  // 224 bits
            WordCount::TwentyFour => 32, // 256 bits
        }
    }

    /// Returns the number of checksum bits for this word count.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use khodpay_bip39::WordCount;
    /// assert_eq!(WordCount::Twelve.checksum_bits(), 4);
    /// assert_eq!(WordCount::TwentyFour.checksum_bits(), 8);
    /// ```
    pub const fn checksum_bits(&self) -> usize {
        match self {
            WordCount::Twelve => 4,
            WordCount::Fifteen => 5,
            WordCount::Eighteen => 6,
            WordCount::TwentyOne => 7,
            WordCount::TwentyFour => 8,
        }
    }

    /// Creates a `WordCount` from the number of words.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWordCount`] if the word count is not valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use khodpay_bip39::WordCount;
    /// assert_eq!(WordCount::from_word_count(12).unwrap(), WordCount::Twelve);
    /// assert_eq!(WordCount::from_word_count(24).unwrap(), WordCount::TwentyFour);
    /// assert!(WordCount::from_word_count(13).is_err());
    /// ```
    pub const fn from_word_count(count: usize) -> Result<Self> {
        match count {
            12 => Ok(WordCount::Twelve),
            15 => Ok(WordCount::Fifteen),
            18 => Ok(WordCount::Eighteen),
            21 => Ok(WordCount::TwentyOne),
            24 => Ok(WordCount::TwentyFour),
            _ => Err(Error::InvalidWordCount { count }),
        }
    }

    /// Creates a `WordCount` from the entropy length in bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEntropyLength`] if the entropy length is not valid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use khodpay_bip39::WordCount;
    /// assert_eq!(WordCount::from_entropy_length(16).unwrap(), WordCount::Twelve);
    /// assert_eq!(WordCount::from_entropy_length(32).unwrap(), WordCount::TwentyFour);
    /// assert!(WordCount::from_entropy_length(10).is_err());
    /// ```
    pub const fn from_entropy_length(length: usize) -> Result<Self> {
        match length {
            16 => Ok(WordCount::Twelve),
            20 => Ok(WordCount::Fifteen),
            24 => Ok(WordCount::Eighteen),
            28 => Ok(WordCount::TwentyOne),
            32 => Ok(WordCount::TwentyFour),
            _ => Err(Error::InvalidEntropyLength { length }),
        }
    }

    /// Returns all valid word count variants.
    ///
    /// This is useful for iteration or validation purposes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use khodpay_bip39::WordCount;
    /// let all_counts = WordCount::all_variants();
    /// assert_eq!(all_counts.len(), 5);
    /// assert!(all_counts.contains(&WordCount::Twelve));
    /// assert!(all_counts.contains(&WordCount::TwentyFour));
    /// ```
    pub const fn all_variants() -> &'static [WordCount] {
        &[
            WordCount::Twelve,
            WordCount::Fifteen,
            WordCount::Eighteen,
            WordCount::TwentyOne,
            WordCount::TwentyFour,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_count_values() {
        assert_eq!(WordCount::Twelve.word_count(), 12);
        assert_eq!(WordCount::Fifteen.word_count(), 15);
        assert_eq!(WordCount::Eighteen.word_count(), 18);
        assert_eq!(WordCount::TwentyOne.word_count(), 21);
        assert_eq!(WordCount::TwentyFour.word_count(), 24);
    }

    #[test]
    fn test_entropy_length_values() {
        assert_eq!(WordCount::Twelve.entropy_length(), 16);
        assert_eq!(WordCount::Fifteen.entropy_length(), 20);
        assert_eq!(WordCount::Eighteen.entropy_length(), 24);
        assert_eq!(WordCount::TwentyOne.entropy_length(), 28);
        assert_eq!(WordCount::TwentyFour.entropy_length(), 32);
    }

    #[test]
    fn test_checksum_bits_values() {
        assert_eq!(WordCount::Twelve.checksum_bits(), 4);
        assert_eq!(WordCount::Fifteen.checksum_bits(), 5);
        assert_eq!(WordCount::Eighteen.checksum_bits(), 6);
        assert_eq!(WordCount::TwentyOne.checksum_bits(), 7);
        assert_eq!(WordCount::TwentyFour.checksum_bits(), 8);
    }

    #[test]
    fn test_from_word_count_valid() {
        assert_eq!(WordCount::from_word_count(12).unwrap(), WordCount::Twelve);
        assert_eq!(WordCount::from_word_count(15).unwrap(), WordCount::Fifteen);
        assert_eq!(WordCount::from_word_count(18).unwrap(), WordCount::Eighteen);
        assert_eq!(
            WordCount::from_word_count(21).unwrap(),
            WordCount::TwentyOne
        );
        assert_eq!(
            WordCount::from_word_count(24).unwrap(),
            WordCount::TwentyFour
        );
    }

    #[test]
    fn test_from_word_count_invalid() {
        assert!(WordCount::from_word_count(0).is_err());
        assert!(WordCount::from_word_count(11).is_err());
        assert!(WordCount::from_word_count(13).is_err());
        assert!(WordCount::from_word_count(25).is_err());
        assert!(WordCount::from_word_count(100).is_err());
    }

    #[test]
    fn test_from_entropy_length_valid() {
        assert_eq!(
            WordCount::from_entropy_length(16).unwrap(),
            WordCount::Twelve
        );
        assert_eq!(
            WordCount::from_entropy_length(20).unwrap(),
            WordCount::Fifteen
        );
        assert_eq!(
            WordCount::from_entropy_length(24).unwrap(),
            WordCount::Eighteen
        );
        assert_eq!(
            WordCount::from_entropy_length(28).unwrap(),
            WordCount::TwentyOne
        );
        assert_eq!(
            WordCount::from_entropy_length(32).unwrap(),
            WordCount::TwentyFour
        );
    }

    #[test]
    fn test_from_entropy_length_invalid() {
        assert!(WordCount::from_entropy_length(0).is_err());
        assert!(WordCount::from_entropy_length(10).is_err());
        assert!(WordCount::from_entropy_length(15).is_err());
        assert!(WordCount::from_entropy_length(33).is_err());
        assert!(WordCount::from_entropy_length(100).is_err());
    }

    #[test]
    fn test_all_variants() {
        let variants = WordCount::all_variants();
        assert_eq!(variants.len(), 5);
        assert_eq!(variants[0], WordCount::Twelve);
        assert_eq!(variants[1], WordCount::Fifteen);
        assert_eq!(variants[2], WordCount::Eighteen);
        assert_eq!(variants[3], WordCount::TwentyOne);
        assert_eq!(variants[4], WordCount::TwentyFour);
    }

    #[test]
    fn test_bidirectional_conversion() {
        for &variant in WordCount::all_variants() {
            // Test word count conversion
            let word_count = variant.word_count();
            assert_eq!(WordCount::from_word_count(word_count).unwrap(), variant);

            // Test entropy length conversion
            let entropy_length = variant.entropy_length();
            assert_eq!(
                WordCount::from_entropy_length(entropy_length).unwrap(),
                variant
            );
        }
    }

    #[test]
    fn test_error_types() {
        match WordCount::from_word_count(13) {
            Err(Error::InvalidWordCount { count }) => assert_eq!(count, 13),
            _ => panic!("Expected InvalidWordCount error"),
        }

        match WordCount::from_entropy_length(10) {
            Err(Error::InvalidEntropyLength { length }) => assert_eq!(length, 10),
            _ => panic!("Expected InvalidEntropyLength error"),
        }
    }
}
