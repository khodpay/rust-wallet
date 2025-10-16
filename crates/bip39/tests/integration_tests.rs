//! Comprehensive integration tests for the BIP39 crate
//!
//! These tests verify the complete workflow from mnemonic generation to seed derivation,
//! ensuring all components work together correctly.

use khodpay_bip39::{Error, Language, Mnemonic, WordCount};

#[test]
fn test_complete_workflow_new_wallet() {
    // Complete workflow: Generate → Validate → Seed → Recover

    // 1. Generate a new mnemonic
    let mnemonic = Mnemonic::generate(WordCount::TwentyFour, Language::English).unwrap();

    // 2. Get the phrase (user would write this down)
    let phrase = mnemonic.phrase();
    assert_eq!(phrase.split_whitespace().count(), 24);

    // 3. Generate seed with passphrase
    let seed = mnemonic.to_seed("my secure passphrase").unwrap();
    assert_eq!(seed.len(), 64);

    // 4. Simulate recovery: parse the phrase back
    let recovered = Mnemonic::from_phrase(phrase, Language::English).unwrap();

    // 5. Verify recovered mnemonic produces same seed
    let recovered_seed = recovered.to_seed("my secure passphrase").unwrap();
    assert_eq!(seed, recovered_seed);

    // 6. Verify entropy matches
    assert_eq!(mnemonic.entropy(), recovered.entropy());
}

#[test]
fn test_complete_workflow_from_entropy() {
    // Workflow: Entropy → Mnemonic → Phrase → Seed

    // 1. Start with known entropy (e.g., from hardware wallet)
    let entropy = [42u8; 32]; // 256 bits

    // 2. Create mnemonic from entropy
    let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
    assert_eq!(mnemonic.word_count(), WordCount::TwentyFour);

    // 3. Get the phrase
    let phrase = mnemonic.phrase();

    // 4. Generate seed
    let seed1 = mnemonic.to_seed("password").unwrap();

    // 5. Verify we can recreate everything from phrase
    let mnemonic2 = Mnemonic::from_phrase(phrase, Language::English).unwrap();
    assert_eq!(mnemonic2.entropy(), &entropy);

    let seed2 = mnemonic2.to_seed("password").unwrap();
    assert_eq!(seed1, seed2);
}

#[test]
fn test_multi_language_workflow() {
    // Test that different languages work end-to-end
    let languages = vec![
        Language::English,
        Language::Japanese,
        Language::Korean,
        Language::Spanish,
        Language::French,
    ];

    for language in languages {
        // Generate mnemonic in specific language
        let mnemonic = Mnemonic::generate(WordCount::Twelve, language).unwrap();

        // Create seed
        let seed = mnemonic.to_seed("test").unwrap();
        assert_eq!(seed.len(), 64);

        // Recover from phrase
        let recovered = Mnemonic::from_phrase(mnemonic.phrase(), language).unwrap();

        // Verify same seed
        let recovered_seed = recovered.to_seed("test").unwrap();
        assert_eq!(seed, recovered_seed);
    }
}

#[test]
fn test_passphrase_variations() {
    // Test that different passphrases produce different seeds
    let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English).unwrap();

    let seed_empty = mnemonic.to_seed("").unwrap();
    let seed_password = mnemonic.to_seed("password").unwrap();
    let seed_unicode = mnemonic.to_seed("пароль 密码 🔑").unwrap();

    // All seeds should be different
    assert_ne!(seed_empty, seed_password);
    assert_ne!(seed_password, seed_unicode);
    assert_ne!(seed_empty, seed_unicode);

    // But deterministic
    assert_eq!(seed_password, mnemonic.to_seed("password").unwrap());
}

#[test]
fn test_all_word_counts_integration() {
    // Test complete workflow for all word counts
    let word_counts = WordCount::all_variants();

    for &word_count in word_counts {
        // Generate
        let mnemonic = Mnemonic::generate(word_count, Language::English).unwrap();

        // Verify
        assert_eq!(mnemonic.word_count(), word_count);
        assert_eq!(
            mnemonic.phrase().split_whitespace().count(),
            word_count.word_count()
        );

        // Create seed
        let seed = mnemonic.to_seed("").unwrap();
        assert_eq!(seed.len(), 64);

        // Recover
        let recovered = Mnemonic::from_phrase(mnemonic.phrase(), Language::English).unwrap();
        assert_eq!(recovered.word_count(), word_count);

        // Same seed
        let recovered_seed = recovered.to_seed("").unwrap();
        assert_eq!(seed, recovered_seed);
    }
}

#[test]
fn test_error_handling_integration() {
    // Test error cases in realistic scenarios

    // Invalid entropy length
    let result = Mnemonic::new(&[0u8; 15], Language::English);
    assert!(matches!(result, Err(Error::InvalidEntropyLength { .. })));

    // Invalid phrase
    let result = Mnemonic::from_phrase("invalid words here not bip39", Language::English);
    assert!(result.is_err());

    // Invalid checksum
    let result = Mnemonic::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        Language::English
    );
    assert!(matches!(result, Err(Error::InvalidChecksum)));

    // Wrong language
    let english_mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English).unwrap();
    let result = Mnemonic::from_phrase(english_mnemonic.phrase(), Language::Japanese);
    assert!(result.is_err());
}

#[test]
fn test_deterministic_wallet_scenario() {
    // Simulate deterministic wallet scenario
    // Same entropy → Same mnemonic → Same seed → Same keys

    let master_entropy = [123u8; 16];

    // Create wallet 1
    let wallet1 = Mnemonic::new(&master_entropy, Language::English).unwrap();
    let seed1 = wallet1.to_seed("").unwrap();

    // Simulate wallet recovery on different device
    let phrase_backup = wallet1.phrase().to_string();

    // Create wallet 2 from backup
    let wallet2 = Mnemonic::from_phrase(&phrase_backup, Language::English).unwrap();
    let seed2 = wallet2.to_seed("").unwrap();

    // Verify complete match
    assert_eq!(wallet1.entropy(), wallet2.entropy());
    assert_eq!(wallet1.phrase(), wallet2.phrase());
    assert_eq!(seed1, seed2);
}

#[test]
fn test_hardware_wallet_integration() {
    // Simulate hardware wallet providing entropy

    // Hardware wallet generates entropy
    let hw_entropy = [0xAB; 32]; // 256 bits from hardware RNG

    // Software wallet creates mnemonic
    let mnemonic = Mnemonic::new(&hw_entropy, Language::English).unwrap();

    // User backs up the phrase
    let backup_phrase = mnemonic.phrase().to_string();

    // Later, restore from backup
    let restored = Mnemonic::from_phrase(&backup_phrase, Language::English).unwrap();

    // Verify entropy matches what hardware wallet generated
    assert_eq!(restored.entropy(), &hw_entropy);

    // Generate seed for key derivation
    let seed = restored.to_seed("hardware wallet passphrase").unwrap();
    assert_eq!(seed.len(), 64);
}

#[test]
fn test_concurrent_mnemonic_generation() {
    // Verify thread safety by generating mnemonics concurrently
    use std::thread;

    let handles: Vec<_> = (0..10)
        .map(|_| {
            thread::spawn(|| {
                let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English).unwrap();
                let seed = mnemonic.to_seed("test").unwrap();
                (mnemonic.phrase().to_string(), seed)
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All mnemonics should be different (extremely high probability)
    for i in 0..results.len() {
        for j in (i + 1)..results.len() {
            assert_ne!(results[i].0, results[j].0, "Mnemonics should be unique");
        }
    }
}

#[test]
fn test_bip39_test_vectors() {
    // Test with known BIP39 test vectors
    // These are from the official BIP39 specification

    // Vector 1: All zeros entropy
    let entropy = [0u8; 16];
    let mnemonic = Mnemonic::new(&entropy, Language::English).unwrap();
    let expected_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert_eq!(mnemonic.phrase(), expected_phrase);

    // Verify seed generation (without passphrase)
    let seed = mnemonic.to_seed("").unwrap();
    assert_eq!(seed.len(), 64);

    // Vector should be recoverable
    let recovered = Mnemonic::from_phrase(expected_phrase, Language::English).unwrap();
    assert_eq!(recovered.entropy(), &entropy);
}

#[test]
fn test_cross_constructor_compatibility() {
    // Verify all constructors produce compatible mnemonics
    let entropy = [55u8; 16];

    // Via new()
    let mnemonic1 = Mnemonic::new(&entropy, Language::English).unwrap();
    let phrase = mnemonic1.phrase().to_string();
    let seed1 = mnemonic1.to_seed("test").unwrap();

    // Via from_phrase()
    let mnemonic2 = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
    let seed2 = mnemonic2.to_seed("test").unwrap();

    // Both should be identical
    assert_eq!(mnemonic1.entropy(), mnemonic2.entropy());
    assert_eq!(mnemonic1.phrase(), mnemonic2.phrase());
    assert_eq!(seed1, seed2);

    // Via generate() should work with same workflow
    let mnemonic3 = Mnemonic::generate(WordCount::Twelve, Language::English).unwrap();
    let phrase3 = mnemonic3.phrase().to_string();
    let seed3 = mnemonic3.to_seed("test").unwrap();

    let mnemonic4 = Mnemonic::from_phrase(&phrase3, Language::English).unwrap();
    let seed4 = mnemonic4.to_seed("test").unwrap();

    assert_eq!(mnemonic3.entropy(), mnemonic4.entropy());
    assert_eq!(seed3, seed4);
}
