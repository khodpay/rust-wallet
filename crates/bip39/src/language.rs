//! Language support for BIP39 mnemonic phrases.
//!
//! This module provides language abstraction for BIP39 word lists, allowing
//! support for multiple languages while maintaining a clean API.
//!
//! # Supported Languages
//!
//! Currently supported languages match the BIP39 specification:
//! - English (default and most widely used)
//! - Japanese, Korean, French, Italian, Spanish, etc. (via upstream crate)
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip39::{Language, validate_phrase_in_language};
//!
//! // Validate English mnemonic (most common)
//! let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! assert!(validate_phrase_in_language(phrase, Language::English).is_ok());
//!
//! // Future: Support for other languages
//! // assert!(validate_phrase_in_language(japanese_phrase, Language::Japanese).is_ok());
//! ```

/// Supported languages for BIP39 mnemonic phrases.
///
/// This enum represents all languages supported by the BIP39 specification.
/// Each language has its own 2048-word list for generating and validating
/// mnemonic phrases.
///
/// # Default Language
///
/// [`English`] is the default and most widely supported language across
/// cryptocurrency applications and hardware wallets.
///
/// [`English`]: Language::English
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// English language word list.
    ///
    /// This is the default and most commonly used language for BIP39 mnemonics.
    /// Supported by virtually all cryptocurrency wallets and applications.
    /// 
    /// The English word list contains 2048 words, each 3-8 characters long,
    /// chosen to be unambiguous and easy to distinguish.
    English,

    /// Japanese language word list.
    ///
    /// Uses hiragana characters and is popular in Japan.
    /// Each word in the Japanese word list is carefully chosen to be
    /// unambiguous when written in hiragana.
    Japanese,

    /// Korean language word list.
    ///
    /// Uses hangul (Korean alphabet) characters for Korean users.
    /// Designed to avoid similar-looking or similar-sounding words.
    Korean,

    /// French language word list.
    ///
    /// Uses French words with proper accents and diacritics.
    /// Words are chosen to be clear and unambiguous in French.
    French,

    /// Italian language word list.
    ///
    /// Uses Italian words selected for clarity and distinction.
    /// Avoids words that might be confused with each other.
    Italian,

    /// Spanish language word list.
    ///
    /// Uses Spanish words carefully selected to avoid ambiguity.
    /// Includes proper Spanish accents and spelling.
    Spanish,

    /// Simplified Chinese language word list.
    ///
    /// Uses simplified Chinese characters (mainland China standard).
    /// Each character/word is chosen for uniqueness and clarity.
    SimplifiedChinese,

    /// Traditional Chinese language word list.
    ///
    /// Uses traditional Chinese characters (Taiwan/Hong Kong standard).
    /// Characters selected to be easily distinguishable.
    TraditionalChinese,

    /// Czech language word list.
    ///
    /// Uses Czech words with proper diacritics and Czech spelling.
    /// Words chosen to be unambiguous in Czech language context.
    Czech,
}

impl Language {
    /// Returns the default language (English).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use khodpay_bip39::Language;
    /// assert_eq!(Language::default(), Language::English);
    /// ```
    pub const fn default() -> Self {
        Language::English
    }

    /// Returns all supported language variants.
    ///
    /// This is useful for iteration or UI language selection.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use khodpay_bip39::Language;
    /// let languages = Language::all_variants();
    /// assert!(languages.contains(&Language::English));
    /// assert!(languages.contains(&Language::Japanese));
    /// assert_eq!(languages.len(), 9);
    /// ```
    pub const fn all_variants() -> &'static [Language] {
        &[
            Language::English,
            Language::Japanese,
            Language::Korean,
            Language::French,
            Language::Italian,
            Language::Spanish,
            Language::SimplifiedChinese,
            Language::TraditionalChinese,
            Language::Czech,
        ]
    }

    /// Returns the language name as a string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use khodpay_bip39::Language;
    /// assert_eq!(Language::English.name(), "English");
    /// ```
    pub const fn name(&self) -> &'static str {
        match self {
            Language::English => "English",
            Language::Japanese => "Japanese",
            Language::Korean => "Korean",
            Language::French => "French",
            Language::Italian => "Italian",
            Language::Spanish => "Spanish",
            Language::SimplifiedChinese => "Simplified Chinese",
            Language::TraditionalChinese => "Traditional Chinese",
            Language::Czech => "Czech",
        }
    }

    /// Converts our Language enum to the upstream crate's Language type.
    ///
    /// This is an internal conversion method used to interface with the
    /// upstream BIP39 crate while maintaining our own API.
    /// 
    /// With the `all-languages` feature enabled, all BIP39 standard languages
    /// are now properly supported and mapped to their upstream variants.
    pub(crate) const fn to_upstream(self) -> bip39_upstream::Language {
        match self {
            Language::English => bip39_upstream::Language::English,
            Language::Japanese => bip39_upstream::Language::Japanese,
            Language::Korean => bip39_upstream::Language::Korean,
            Language::French => bip39_upstream::Language::French,
            Language::Italian => bip39_upstream::Language::Italian,
            Language::Spanish => bip39_upstream::Language::Spanish,
            Language::SimplifiedChinese => bip39_upstream::Language::SimplifiedChinese,
            Language::TraditionalChinese => bip39_upstream::Language::TraditionalChinese,
            Language::Czech => bip39_upstream::Language::Czech,
        }
    }
}

impl Default for Language {
    /// Returns the default language (English).
    fn default() -> Self {
        Language::English
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_default() {
        assert_eq!(Language::default(), Language::English);
        assert_eq!(Language::default(), Language::default());
    }

    #[test]
    fn test_language_name() {
        assert_eq!(Language::English.name(), "English");
        assert_eq!(Language::Japanese.name(), "Japanese");
        assert_eq!(Language::Korean.name(), "Korean");
        assert_eq!(Language::French.name(), "French");
        assert_eq!(Language::Italian.name(), "Italian");
        assert_eq!(Language::Spanish.name(), "Spanish");
        assert_eq!(Language::SimplifiedChinese.name(), "Simplified Chinese");
        assert_eq!(Language::TraditionalChinese.name(), "Traditional Chinese");
        assert_eq!(Language::Czech.name(), "Czech");
    }

    #[test]
    fn test_all_variants() {
        let variants = Language::all_variants();
        assert_eq!(variants.len(), 9);
        assert!(variants.contains(&Language::English));
        assert!(variants.contains(&Language::Japanese));
        assert!(variants.contains(&Language::Korean));
        assert!(variants.contains(&Language::French));
        assert!(variants.contains(&Language::Italian));
        assert!(variants.contains(&Language::Spanish));
        assert!(variants.contains(&Language::SimplifiedChinese));
        assert!(variants.contains(&Language::TraditionalChinese));
        assert!(variants.contains(&Language::Czech));
    }

    #[test]
    fn test_to_upstream_conversion() {
        // Test that our enum values convert correctly to upstream types
        assert_eq!(Language::English.to_upstream(), bip39_upstream::Language::English);
        assert_eq!(Language::Japanese.to_upstream(), bip39_upstream::Language::Japanese);
        assert_eq!(Language::Korean.to_upstream(), bip39_upstream::Language::Korean);
        assert_eq!(Language::French.to_upstream(), bip39_upstream::Language::French);
        assert_eq!(Language::Italian.to_upstream(), bip39_upstream::Language::Italian);
        assert_eq!(Language::Spanish.to_upstream(), bip39_upstream::Language::Spanish);
        assert_eq!(Language::SimplifiedChinese.to_upstream(), bip39_upstream::Language::SimplifiedChinese);
        assert_eq!(Language::TraditionalChinese.to_upstream(), bip39_upstream::Language::TraditionalChinese);
        assert_eq!(Language::Czech.to_upstream(), bip39_upstream::Language::Czech);
    }

    #[test]
    fn test_language_equality() {
        assert_eq!(Language::English, Language::English);
        
        // Test that copies are equal
        let lang1 = Language::English;
        let lang2 = lang1;
        assert_eq!(lang1, lang2);
    }

    #[test]
    fn test_language_debug() {
        // Test that Debug trait works (for debugging/logging)
        let debug_output = format!("{:?}", Language::English);
        assert!(debug_output.contains("English"));
    }
}
