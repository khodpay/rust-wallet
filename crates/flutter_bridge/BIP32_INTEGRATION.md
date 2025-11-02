# BIP32 Integration in Flutter Bridge

This document describes the BIP32 functionality available in the `flutter_bridge` crate.

## Overview

BIP32 (Bitcoin Improvement Proposal 32) defines Hierarchical Deterministic (HD) wallets. This allows generating a tree of key pairs from a single seed, enabling organized key management and backup.

## What's Included

### Enums

#### `NetworkType`
Defines the blockchain network for key generation.

```rust
pub enum NetworkType {
    BitcoinMainnet,
    BitcoinTestnet,
}
```

### Object-Oriented API

#### `ExtendedPrivateKey` Struct
Wrapper for BIP32 extended private keys with full derivation capabilities.

**Creation Methods:**

##### `from_seed(seed: Vec<u8>, network: NetworkType) -> Result<ExtendedPrivateKey, String>`
Create a master key from a raw seed (typically from BIP39).

```rust
let seed = vec![0u8; 64]; // 512-bit seed from BIP39
let master_key = ExtendedPrivateKey::from_seed(
    seed,
    NetworkType::BitcoinMainnet
)?;
```

##### `from_mnemonic(mnemonic: &Mnemonic, passphrase: Option<String>, network: NetworkType) -> Result<ExtendedPrivateKey, String>`
Create a master key directly from a BIP39 mnemonic.

```rust
let mnemonic = Mnemonic::generate(12)?;
let master_key = ExtendedPrivateKey::from_mnemonic(
    &mnemonic,
    Some("my_passphrase".to_string()),
    NetworkType::BitcoinMainnet
)?;
```

##### `from_string(s: String) -> Result<ExtendedPrivateKey, String>`
Parse an extended private key from its serialized form (xprv... format).

```rust
let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
let key = ExtendedPrivateKey::from_string(xprv.to_string())?;
```

**Serialization:**

##### `to_extended_string() -> String`
Serialize the key to xprv... format.

```rust
let xprv = master_key.to_extended_string();
// Returns: "xprv9s21ZrQH143K..."
```

**Key Information:**

##### `network() -> NetworkType`
Get the network this key belongs to.

```rust
let network = key.network();
assert_eq!(network, NetworkType::BitcoinMainnet);
```

##### `depth() -> u8`
Get the depth in the derivation tree (0 for master key).

```rust
let depth = master_key.depth();
assert_eq!(depth, 0); // Master key
```

##### `parent_fingerprint() -> Vec<u8>`
Get the parent key's fingerprint (4 bytes).

```rust
let parent_fp = key.parent_fingerprint();
```

##### `fingerprint() -> Vec<u8>`
Get this key's fingerprint (4 bytes).

```rust
let fp = key.fingerprint();
```

##### `child_number_index() -> u32`
Get the child number index.

```rust
let index = child_key.child_number_index();
```

##### `is_hardened() -> bool`
Check if this is a hardened derivation.

```rust
if key.is_hardened() {
    println!("This is a hardened key");
}
```

**Derivation Methods:**

##### `derive_child(index: u32, hardened: bool) -> Result<ExtendedPrivateKey, String>`
Derive a single child key.

```rust
// Derive hardened child at index 0 (0')
let child = master_key.derive_child(0, true)?;

// Derive normal child at index 0
let normal_child = master_key.derive_child(0, false)?;
```

##### `derive_path(path: String) -> Result<ExtendedPrivateKey, String>`
Derive using a BIP32 path string.

```rust
// Derive BIP44 Bitcoin account 0
let account = master_key.derive_path("m/44'/0'/0'".to_string())?;

// Derive first receiving address
let address = account.derive_path("m/0/0".to_string())?;
```

**Conversion:**

##### `to_extended_public_key() -> ExtendedPublicKey`
Convert to the corresponding extended public key.

```rust
let xpub = xprv.to_extended_public_key();
```

#### `ExtendedPublicKey` Struct
Wrapper for BIP32 extended public keys (watch-only).

**Creation Methods:**

##### `from_string(s: String) -> Result<ExtendedPublicKey, String>`
Parse from xpub... format.

```rust
let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
let pub_key = ExtendedPublicKey::from_string(xpub.to_string())?;
```

**Serialization:**

##### `to_extended_string() -> String`
Serialize to xpub... format.

```rust
let xpub = pub_key.to_extended_string();
```

**Key Information:**
Same methods as `ExtendedPrivateKey`: `network()`, `depth()`, `parent_fingerprint()`, `fingerprint()`, `child_number_index()`, `is_hardened()`

**Derivation Methods:**

##### `derive_child(index: u32) -> Result<ExtendedPublicKey, String>`
Derive a non-hardened child public key.

```rust
// Only normal (non-hardened) derivation is possible with public keys
let child = xpub.derive_child(0)?;
```

##### `derive_path(path: String) -> Result<ExtendedPublicKey, String>`
Derive using a path (only non-hardened paths allowed).

```rust
// Derive receiving addresses (no hardened derivation)
let address_key = xpub.derive_path("m/0/0".to_string())?;
```

### Utility Functions

#### `create_master_key(mnemonic: String, passphrase: Option<String>, network: NetworkType) -> Result<String, String>`
Create a master key and return it as a string.

```rust
let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let xprv = create_master_key(
    mnemonic.to_string(),
    None,
    NetworkType::BitcoinMainnet
)?;
```

#### `derive_key(extended_key: String, derivation_path: String) -> Result<String, String>`
Derive a child key from an extended key string.

```rust
let child_xprv = derive_key(
    master_xprv,
    "m/44'/0'/0'".to_string()
)?;
```

#### `get_public_key(extended_private_key: String) -> Result<String, String>`
Get the public key from a private key string.

```rust
let xpub = get_public_key(xprv)?;
```

#### `get_address(extended_private_key: String, address_index: u32) -> Result<String, String>`
Derive an address at a specific index (uses m/0/index path).

```rust
let address_key = get_address(account_xprv, 0)?;
```

## Usage Examples

### Example 1: Create Master Key from Mnemonic
```rust
// Generate mnemonic
let mnemonic = Mnemonic::generate(12)?;

// Create master key
let master_key = ExtendedPrivateKey::from_mnemonic(
    &mnemonic,
    None,  // No passphrase
    NetworkType::BitcoinMainnet
)?;

// Get serialized form
let xprv = master_key.to_extended_string();
println!("Master key: {}", xprv);
```

### Example 2: Derive Child Keys
```rust
// Create master key
let master = ExtendedPrivateKey::from_seed(seed, NetworkType::BitcoinMainnet)?;

// Derive purpose level (BIP44 = 44')
let purpose = master.derive_child(44, true)?;

// Derive coin type (Bitcoin = 0')
let coin = purpose.derive_child(0, true)?;

// Derive account (first account = 0')
let account = coin.derive_child(0, true)?;

// Derive external chain
let external = account.derive_child(0, false)?;

// Derive first address
let address = external.derive_child(0, false)?;
```

### Example 3: Use Path Strings
```rust
// Much simpler than manual derivation
let account = master_key.derive_path("m/44'/0'/0'".to_string())?;
let first_address = account.derive_path("m/0/0".to_string())?;
let second_address = account.derive_path("m/0/1".to_string())?;
let first_change = account.derive_path("m/1/0".to_string())?;
```

### Example 4: Public Key Derivation (Watch-Only)
```rust
// Get account public key
let account_xprv = master.derive_path("m/44'/0'/0'".to_string())?;
let account_xpub = account_xprv.to_extended_public_key();

// Share xpub for watch-only wallet (safe to share)
let xpub_string = account_xpub.to_extended_string();

// Derive receiving addresses without private key
let addr0 = account_xpub.derive_child(0)?.derive_child(0)?;
let addr1 = account_xpub.derive_child(0)?.derive_child(1)?;
```

### Example 5: Key Metadata
```rust
let master = ExtendedPrivateKey::from_seed(seed, NetworkType::BitcoinMainnet)?;
let child = master.derive_child(0, true)?;

// Check key properties
println!("Master depth: {}", master.depth()); // 0
println!("Child depth: {}", child.depth());   // 1
println!("Is hardened: {}", child.is_hardened()); // true
println!("Child index: {}", child.child_number_index()); // 0
println!("Network: {:?}", child.network());
```

### Example 6: Utility Functions
```rust
// Quick master key creation
let xprv = create_master_key(
    mnemonic_phrase,
    Some("passphrase".to_string()),
    NetworkType::BitcoinMainnet
)?;

// Quick derivation
let account_xprv = derive_key(xprv.clone(), "m/44'/0'/0'".to_string())?;

// Get public key
let xpub = get_public_key(account_xprv.clone())?;

// Get address
let address = get_address(account_xprv, 0)?;
```

## BIP32 Path Format

### Path Structure
```
m / level1 / level2 / level3 / ...
```

- `m` = master key
- `/` = derivation separator
- `'` or `h` = hardened derivation (adds 2^31 to index)

### Examples
- `m/0` - First normal child of master
- `m/0'` - First hardened child of master
- `m/44'/0'/0'` - BIP44 Bitcoin account 0
- `m/44'/0'/0'/0/0` - First receiving address of account 0

### Hardened vs Normal Derivation

**Hardened ('):**
- Requires private key
- More secure
- Used for account-level derivation
- Index: 2^31 + n (2147483648 + n)

**Normal:**
- Can be derived from public key
- Used for address-level derivation
- Index: 0 to 2^31-1

## Security Considerations

### 🔒 Private Key Security

1. **Never expose private keys**
   - xprv strings contain private key material
   - Never log, transmit, or store unencrypted
   - Use secure memory when possible

2. **Master key protection**
   - Master key can derive all child keys
   - Highest security priority
   - Consider hardware wallet storage

3. **Hardened derivation**
   - Use hardened derivation for account levels
   - Prevents parent key exposure if child key leaks

### 🔓 Public Key Usage

1. **Safe to share**
   - xpub can be shared for watch-only wallets
   - Cannot derive private keys from xpub
   - Can only derive non-hardened children

2. **Privacy considerations**
   - xpub reveals all derived addresses
   - Consider privacy implications before sharing

3. **Gap limit**
   - Follow BIP44 gap limit (20 addresses)
   - Important for wallet recovery

## Network Compatibility

Keys are network-specific:
- **Mainnet keys** start with `xprv`/`xpub`
- **Testnet keys** start with `tprv`/`tpub`
- Cannot mix networks in derivation

## Error Handling

```rust
match ExtendedPrivateKey::from_string(user_input) {
    Ok(key) => {
        // Valid key
        println!("Key depth: {}", key.depth());
    }
    Err(e) => {
        // Invalid key format
        println!("Error: {}", e);
    }
}
```

## Flutter/Dart Usage

After building and generating bindings:

```dart
// Create master key
final mnemonic = await Mnemonic.generate(wordCount: 12);
final masterKey = await ExtendedPrivateKey.fromMnemonic(
  mnemonic: mnemonic,
  passphrase: null,
  network: NetworkType.BitcoinMainnet,
);

// Derive child
final child = await masterKey.deriveChild(index: 0, hardened: true);

// Use path
final account = await masterKey.derivePath(path: "m/44'/0'/0'");

// Get public key
final pubKey = masterKey.toExtendedPublicKey();
final xpub = pubKey.toExtendedString();
```

## Standards Compliance

This implementation follows:
- **BIP32**: Hierarchical Deterministic Wallets
- **SLIP-0010**: Universal private key derivation
- **Secp256k1**: Elliptic curve for Bitcoin
- **HMAC-SHA512**: Key derivation function

## Related Documentation

- [BIP39_INTEGRATION.md](./BIP39_INTEGRATION.md) - Mnemonic generation
- [BIP44_INTEGRATION.md](./BIP44_INTEGRATION.md) - Multi-account hierarchy
- [Official BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
