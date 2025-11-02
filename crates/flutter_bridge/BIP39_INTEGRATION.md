# BIP39 Integration in Flutter Bridge

This document describes the BIP39 functionality available in the `flutter_bridge` crate.

## Overview

BIP39 (Bitcoin Improvement Proposal 39) defines the standard for mnemonic code generation for deterministic keys. This implementation provides a secure way to generate and manage mnemonic phrases (seed phrases) for cryptocurrency wallets.

## What's Included

### Object-Oriented API

#### `Mnemonic` Struct
A wrapper around the Rust BIP39 mnemonic implementation with full OOP interface.

**Methods:**

##### `generate(word_count: u32) -> Result<Mnemonic, String>`
Generate a new random mnemonic with the specified word count.

```rust
// Generate a 12-word mnemonic
let mnemonic = Mnemonic::generate(12)?;

// Generate a 24-word mnemonic (more secure)
let mnemonic = Mnemonic::generate(24)?;
```

**Supported word counts:**
- 12 words (128 bits of entropy)
- 15 words (160 bits of entropy)
- 18 words (192 bits of entropy)
- 21 words (224 bits of entropy)
- 24 words (256 bits of entropy)

##### `from_phrase(phrase: String) -> Result<Mnemonic, String>`
Parse and validate an existing mnemonic phrase.

```rust
let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::from_phrase(phrase.to_string())?;
```

##### `to_phrase() -> String`
Convert the mnemonic to a string phrase.

```rust
let phrase = mnemonic.to_phrase();
println!("Your mnemonic: {}", phrase);
```

##### `word_count() -> u32`
Get the number of words in the mnemonic.

```rust
let count = mnemonic.word_count();
assert_eq!(count, 12);
```

##### `is_valid() -> bool`
Check if the mnemonic is valid (always returns true for constructed mnemonics).

```rust
if mnemonic.is_valid() {
    println!("Mnemonic is valid");
}
```

### Utility Functions

#### `generate_mnemonic(word_count: u32) -> Result<String, String>`
Generate a new mnemonic and return it as a string directly.

```rust
// Quick way to generate a mnemonic phrase
let phrase = generate_mnemonic(12)?;
println!("Generated: {}", phrase);
```

#### `validate_mnemonic(phrase: String) -> bool`
Validate a mnemonic phrase without creating a Mnemonic object.

```rust
let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
if validate_mnemonic(phrase.to_string()) {
    println!("Valid mnemonic!");
}
```

## Usage Examples

### Example 1: Generate and Store Mnemonic
```rust
// Generate a new 24-word mnemonic
let mnemonic = Mnemonic::generate(24)?;

// Get the phrase to display to user
let phrase = mnemonic.to_phrase();
println!("IMPORTANT: Write down these words:");
println!("{}", phrase);

// Verify word count
assert_eq!(mnemonic.word_count(), 24);
```

### Example 2: Restore from Existing Phrase
```rust
// User enters their existing mnemonic
let user_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Validate and create mnemonic
let mnemonic = Mnemonic::from_phrase(user_phrase.to_string())?;

// Use it to create wallet keys
let master_key = ExtendedPrivateKey::from_mnemonic(
    &mnemonic,
    Some("optional_passphrase".to_string()),
    NetworkType::BitcoinMainnet
)?;
```

### Example 3: Quick Validation
```rust
// Quick validation without creating object
let phrase = "invalid mnemonic phrase";
if !validate_mnemonic(phrase.to_string()) {
    println!("Invalid mnemonic! Please check your words.");
}
```

### Example 4: Generate with Different Lengths
```rust
// For standard security (most common)
let standard = generate_mnemonic(12)?;

// For high security
let high_security = generate_mnemonic(24)?;

// Validate both
assert!(validate_mnemonic(standard.clone()));
assert!(validate_mnemonic(high_security.clone()));
```

## Integration with BIP32

BIP39 mnemonics are typically used to generate BIP32 master keys:

```rust
// Generate mnemonic
let mnemonic = Mnemonic::generate(12)?;

// Create master key from mnemonic
let master_key = ExtendedPrivateKey::from_mnemonic(
    &mnemonic,
    None,  // No passphrase
    NetworkType::BitcoinMainnet
)?;

// Now you can derive child keys
let child = master_key.derive_child(0, true)?;
```

## Integration with BIP44

BIP39 mnemonics are also used with BIP44 wallets:

```rust
// Generate mnemonic
let phrase = generate_mnemonic(12)?;

// Create BIP44 wallet
let mut wallet = Bip44Wallet::from_mnemonic(
    phrase,
    None,  // No passphrase
    NetworkType::BitcoinMainnet
)?;

// Derive accounts
let account = wallet.get_account(
    PurposeType::BIP84,
    CoinType::Bitcoin,
    0
)?;
```

## Security Considerations

### ⚠️ Important Security Notes

1. **Mnemonic Storage**
   - Never store mnemonics in plain text
   - Never log mnemonics
   - Never transmit mnemonics over insecure channels
   - Use secure storage mechanisms (encrypted storage, hardware wallets)

2. **Passphrase (BIP39 Extension)**
   - Optional passphrase provides additional security
   - Acts as a "25th word"
   - Different passphrases generate different wallets
   - If lost, wallet cannot be recovered even with mnemonic

3. **Backup**
   - Users should write down mnemonics on paper
   - Store in multiple secure locations
   - Never take photos or screenshots
   - Consider using metal backup plates for fire/water resistance

4. **Validation**
   - Always validate user-entered mnemonics
   - Check for typos and invalid words
   - Use the built-in validation functions

5. **Entropy**
   - 12 words = 128 bits (adequate for most use cases)
   - 24 words = 256 bits (maximum security)
   - Never use custom/weak entropy sources

## Language Support

Currently, the Flutter bridge uses **English** wordlist by default. The underlying Rust library supports multiple languages, but the bridge is configured for English to ensure consistency across platforms.

## Error Handling

All mnemonic operations return `Result` types:

```rust
match Mnemonic::from_phrase(user_input) {
    Ok(mnemonic) => {
        // Valid mnemonic, proceed
        println!("Mnemonic accepted");
    }
    Err(e) => {
        // Invalid mnemonic, show error to user
        println!("Error: {}", e);
    }
}
```

## Testing

```rust
// Test mnemonic generation
let mnemonic = Mnemonic::generate(12)?;
assert_eq!(mnemonic.word_count(), 12);
assert!(mnemonic.is_valid());

// Test known valid mnemonic
let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::from_phrase(test_phrase.to_string())?;
assert_eq!(mnemonic.to_phrase(), test_phrase);

// Test validation
assert!(validate_mnemonic(test_phrase.to_string()));
assert!(!validate_mnemonic("invalid phrase".to_string()));
```

## Flutter/Dart Usage

After building and generating bindings, use in Flutter:

```dart
// Generate new mnemonic
final mnemonic = await Mnemonic.generate(wordCount: 12);
final phrase = mnemonic.toPhrase();

// Restore from phrase
final restored = await Mnemonic.fromPhrase(phrase: userInput);

// Quick validation
final isValid = await validateMnemonic(phrase: userInput);

// Quick generation
final quickPhrase = await generateMnemonic(wordCount: 24);
```

## Standards Compliance

This implementation follows:
- **BIP39**: Mnemonic code for generating deterministic keys
- **English wordlist**: 2048 words from the official BIP39 specification
- **Checksum validation**: Automatic checksum verification
- **Entropy standards**: Proper entropy generation using secure RNG

## Related Documentation

- [BIP32_INTEGRATION.md](./BIP32_INTEGRATION.md) - HD key derivation
- [BIP44_INTEGRATION.md](./BIP44_INTEGRATION.md) - Multi-account hierarchy
- [Official BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
