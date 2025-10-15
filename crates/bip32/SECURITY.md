# Security Policy and Best Practices

## Overview

This document outlines security considerations, best practices, and the security model for the BIP32 hierarchical deterministic wallet library. **Reading and understanding this document is critical before using this library in production.**

## Table of Contents

- [Security Model](#security-model)
- [Threat Model](#threat-model)
- [Best Practices](#best-practices)
- [Common Pitfalls](#common-pitfalls)
- [Security Features](#security-features)
- [Vulnerability Reporting](#vulnerability-reporting)
- [Audit Status](#audit-status)

## Security Model

### What This Library Provides

✅ **Cryptographic Correctness**
- Implements BIP32 specification accurately
- Uses audited cryptographic libraries (`secp256k1`, `hmac`, `sha2`)
- Validated against official test vectors
- Cross-compatible with major implementations

✅ **Memory Safety**
- 100% safe Rust (no `unsafe` code)
- Automatic memory management via Rust's ownership system
- Sensitive data cleared using `zeroize` on drop

✅ **Type Safety**
- Compile-time guarantees for key types and networks
- Prevents mixing mainnet/testnet keys
- Clear distinction between public and private keys

### What This Library Does NOT Provide

❌ **Physical Security**
- Cannot protect against hardware keyloggers
- Cannot prevent physical access to memory
- Cannot protect against side-channel attacks on hardware

❌ **Application-Level Security**
- Does not manage key storage (use secure key stores)
- Does not handle authentication or authorization
- Does not protect against application logic bugs

❌ **Network Security**
- Does not implement secure communication protocols
- Does not protect keys during network transmission
- Does not provide key distribution mechanisms

## Threat Model

### Protected Against

✅ **Software Vulnerabilities**
- Memory safety bugs (buffer overflows, use-after-free)
- Integer overflow/underflow in key derivation
- Incorrect cryptographic implementations

✅ **Cryptographic Attacks**
- Weak key generation (uses proper randomness)
- Invalid curve points (validation on all operations)
- Parent key exposure via child keys (hardened derivation)

✅ **Side-Channel Resistance**
- Memory cleared after use (`zeroize`)
- Constant-time operations for sensitive data where possible

### NOT Protected Against

⚠️ **Physical Attacks**
- Cold boot attacks
- DMA attacks
- Hardware tampering

⚠️ **Social Engineering**
- Phishing for seeds/mnemonics
- Malware/keyloggers
- Compromised development environments

⚠️ **Implementation Misuse**
- Weak seed generation by application
- Improper key storage by application
- Logging sensitive data in application code

## Best Practices

### 1. Seed Generation

#### ✅ DO

```rust
// Use cryptographically secure random number generator
use bip39::{Mnemonic, WordCount, Language};

let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;
```

#### ❌ DON'T

```rust
// NEVER use weak randomness
let bad_seed = b"not-random-at-all-very-bad-seed-dont-do-this";

// NEVER use predictable seeds
let bad_seed = format!("seed-{}", user_id);

// NEVER reuse seeds across different purposes
```

### 2. Key Storage

#### ✅ DO

- **Use Hardware Security Modules (HSM)** for production systems
- **Use OS key stores** (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- **Encrypt private keys** at rest with strong encryption (AES-256-GCM)
- **Use access controls** to limit who can read keys
- **Implement key rotation** policies

#### ❌ DON'T

- **Store keys in plaintext files**
- **Store keys in databases without encryption**
- **Store keys in version control** (git, etc.)
- **Log private keys or seeds** (even in debug mode)
- **Share keys via email, chat, or other insecure channels**

### 3. Derivation Path Strategy

#### ✅ DO - Use Hardened Derivation for Upper Levels

```rust
// BIP-44 standard: m/purpose'/coin_type'/account'/change/address_index
// Upper 3 levels are hardened for security
let path = DerivationPath::from_str("m/44'/0'/0'/0/0")?;
```

**Why**: Hardened derivation prevents parent key exposure if a child key is compromised.

#### ❌ DON'T - Use Normal Derivation for Accounts

```rust
// BAD: Account level should be hardened
let bad_path = DerivationPath::from_str("m/44'/0'/0/0/0")?;
//                                              ^ Should be 0' not 0
```

### 4. Key Lifecycle Management

#### ✅ DO

```rust
use bip32::ExtendedPrivateKey;

{
    let master_key = ExtendedPrivateKey::from_seed(seed, network)?;
    
    // Use the key
    let account = master_key.derive_path(&path)?;
    
    // Key is automatically zeroized when it goes out of scope
}
// master_key memory is now cleared
```

#### ❌ DON'T

```rust
// Don't keep keys in memory longer than necessary
static MASTER_KEY: Option<ExtendedPrivateKey> = None; // Bad!

// Don't clone keys unnecessarily
let unnecessary_copy = master_key.clone(); // Avoid if possible
```

### 5. Network Segregation

#### ✅ DO

```rust
// Always specify the correct network
let mainnet_key = ExtendedPrivateKey::from_seed(seed, Network::BitcoinMainnet)?;
let testnet_key = ExtendedPrivateKey::from_seed(seed, Network::BitcoinTestnet)?;

// Keys will have different serializations (xprv vs tprv)
assert_ne!(mainnet_key.to_string(), testnet_key.to_string());
```

#### ❌ DON'T

```rust
// Don't mix mainnet and testnet keys
let mainnet = Network::BitcoinMainnet;
let testnet = Network::BitcoinTestnet;

// This is confusing and dangerous
if user_mode == "test" {
    let key = ExtendedPrivateKey::from_seed(seed, mainnet)?; // Wrong!
}
```

### 6. Error Handling

#### ✅ DO

```rust
use bip32::Error;

match master_key.derive_path(&path) {
    Ok(key) => {
        // Use key
    }
    Err(Error::MaxDepthExceeded { depth }) => {
        // Handle specific error
        log::error!("Path too deep: {}", depth);
    }
    Err(e) => {
        // Handle other errors
        log::error!("Derivation failed: {}", e);
    }
}
```

#### ❌ DON'T

```rust
// Don't unwrap in production
let key = master_key.derive_path(&path).unwrap(); // Bad!

// Don't ignore errors
let _ = master_key.derive_path(&path); // Bad!

// Don't log sensitive data in errors
log::error!("Failed to derive from seed: {}", hex::encode(seed)); // NEVER!
```

## Common Pitfalls

### 1. Weak Seed Generation

**Problem**: Using predictable or low-entropy seeds.

```rust
// ❌ WRONG
let weak_seed = b"password123";
let master = ExtendedPrivateKey::from_seed(weak_seed, network)?;
```

**Solution**: Always use cryptographically secure random number generators.

```rust
// ✅ CORRECT
use bip39::{Mnemonic, WordCount, Language};

let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;
let master = ExtendedPrivateKey::from_mnemonic(&mnemonic, None, network)?;
```

### 2. Insufficient Key Protection

**Problem**: Storing private keys in plaintext.

```rust
// ❌ WRONG
std::fs::write("master_key.txt", master_key.to_string())?;
```

**Solution**: Encrypt keys before storage.

```rust
// ✅ CORRECT (pseudo-code)
let encrypted = encrypt_aes_256_gcm(&master_key.to_string(), &user_password)?;
secure_storage.store("master_key", encrypted)?;
```

### 3. Parent Key Exposure

**Problem**: Using normal derivation for account-level keys.

```rust
// ❌ WRONG - If account public key + chain code leaked,
// child private keys can be derived
let path = DerivationPath::from_str("m/44/0/0")?; // No hardening!
```

**Solution**: Use hardened derivation for upper levels.

```rust
// ✅ CORRECT
let path = DerivationPath::from_str("m/44'/0'/0'")?; // Hardened
```

### 4. Logging Sensitive Data

**Problem**: Accidentally logging private keys or seeds.

```rust
// ❌ WRONG
log::debug!("Master key: {}", master_key); // NEVER!
println!("Seed: {:?}", seed); // NEVER!
```

**Solution**: Only log public information.

```rust
// ✅ CORRECT
log::debug!("Master xpub: {}", master_key.to_extended_public_key());
log::debug!("Derivation path: {}", path);
```

### 5. Hardcoded Secrets

**Problem**: Hardcoding seeds or keys in source code.

```rust
// ❌ WRONG - Keys in git history forever!
const MASTER_SEED: &[u8] = b"hardcoded-seed-very-bad";
```

**Solution**: Load secrets from secure configuration or environment.

```rust
// ✅ CORRECT
let seed = std::env::var("MASTER_SEED")
    .expect("MASTER_SEED not set");
// Better: load from secure key store
```

### 6. Inadequate Access Controls

**Problem**: Not restricting access to keys.

```rust
// ❌ WRONG - File readable by all users
std::fs::write("/tmp/keys.txt", encrypted_keys)?;
```

**Solution**: Set proper file permissions.

```rust
// ✅ CORRECT (Unix)
use std::os::unix::fs::PermissionsExt;
use std::fs;

fs::write("/secure/path/keys.enc", encrypted_keys)?;
let mut perms = fs::metadata("/secure/path/keys.enc")?.permissions();
perms.set_mode(0o600); // Owner read/write only
fs::set_permissions("/secure/path/keys.enc", perms)?;
```

## Security Features

### Memory Safety

- **No `unsafe` code**: 100% safe Rust
- **Automatic cleanup**: `zeroize` clears sensitive data on drop
- **Ownership model**: Prevents double-free and use-after-free

### Cryptographic Correctness

- **Audited libraries**: Uses `secp256k1`, `hmac`, `sha2`
- **Test vectors**: Validated against BIP32 official vectors
- **Cross-compatibility**: Tested with major implementations

### Type Safety

- **Network types**: Prevents mainnet/testnet mixing
- **Key types**: Clear public/private distinction
- **Path validation**: Enforces depth limits and valid indices

### Side-Channel Resistance

- **Constant-time operations**: Where possible for sensitive operations
- **Memory clearing**: Automatic via `zeroize`
- **No timing leaks**: Careful implementation of comparisons

## Vulnerability Reporting

### Reporting Security Issues

If you discover a security vulnerability, please:

1. **DO NOT** open a public issue
2. **Email**: security@your-domain.com (PGP key available)
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Initial response**: Within 48 hours
- **Status update**: Within 1 week
- **Fix release**: Depends on severity (critical: ASAP)

### Disclosure Policy

- Coordinated disclosure preferred
- 90-day disclosure window (negotiable)
- Credit given to reporters (unless requested otherwise)

## Audit Status

### Current Status

- ✅ **Internal review**: Completed
- ✅ **Test vector validation**: All vectors pass
- ✅ **Cross-compatibility testing**: Verified with major implementations
- ⏳ **External audit**: Pending

### Testing Coverage

- Unit tests: 439+ tests
- Integration tests: 58 test vector tests
- Doc tests: 78+ examples
- Cross-compatibility tests: 11 implementations

## Additional Resources

### Security Standards

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetsecure.org/Cryptographic_Storage_Cheat_Sheet)
- [Bitcoin Wallet Security Best Practices](https://en.bitcoin.it/wiki/Securing_your_wallet)
- [NIST Guidelines for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

### Related BIP Security Considerations

- [BIP32 Security](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#security)
- [BIP39 Security](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#security)
- [BIP44 Security](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#security)

## License

This security policy is part of the BIP32 library and is subject to the same MIT license.

---

**Last Updated**: 2025-10-15

**Remember**: Security is a shared responsibility. This library provides cryptographic primitives, but the overall security of your application depends on how you use these primitives.

🔒 **Stay Safe!**
