# Flutter Rust Bridge - Struct Wrapper Pattern

## Problem

The basic guide only exports functions. This means:
- ❌ No struct methods available in Flutter
- ❌ Must pass strings/primitives only
- ❌ No object-oriented API

## Solution: Wrapper Structs with `#[frb]`

### Example: Wrapping `ExtendedPrivateKey`

```rust
use flutter_rust_bridge::frb;
use khodpay_bip32::{
    ExtendedPrivateKey as RustExtendedPrivateKey,
    ExtendedPublicKey as RustExtendedPublicKey,
    Network, DerivationPath, ChildNumber,
};
use khodpay_bip39::{Mnemonic as RustMnemonic, WordCount, Language};
use std::str::FromStr;

// =============================================================================
// Wrapper Structs (exposed to Flutter)
// =============================================================================

/// Flutter wrapper for ExtendedPrivateKey
#[frb]
pub struct ExtendedPrivateKey {
    inner: RustExtendedPrivateKey,
}

#[frb]
impl ExtendedPrivateKey {
    /// Create master key from seed
    #[frb]
    pub fn from_seed(seed: Vec<u8>, network: NetworkType) -> Result<Self, String> {
        let key = RustExtendedPrivateKey::from_seed(&seed, network.into())
            .map_err(|e| e.to_string())?;
        Ok(Self { inner: key })
    }

    /// Create master key from mnemonic
    #[frb]
    pub fn from_mnemonic(
        mnemonic: &Mnemonic,
        passphrase: Option<String>,
        network: NetworkType,
    ) -> Result<Self, String> {
        let key = RustExtendedPrivateKey::from_mnemonic(
            &mnemonic.inner,
            passphrase.as_deref(),
            network.into(),
        )
        .map_err(|e| e.to_string())?;
        Ok(Self { inner: key })
    }

    /// Get the depth in derivation tree
    #[frb]
    pub fn depth(&self) -> u8 {
        self.inner.depth()
    }

    /// Get the network
    #[frb]
    pub fn network(&self) -> NetworkType {
        self.inner.network().into()
    }

    /// Get parent fingerprint
    #[frb]
    pub fn parent_fingerprint(&self) -> Vec<u8> {
        self.inner.parent_fingerprint().to_vec()
    }

    /// Get child number index
    #[frb]
    pub fn child_number_index(&self) -> u32 {
        match self.inner.child_number() {
            ChildNumber::Normal(n) | ChildNumber::Hardened(n) => n,
        }
    }

    /// Check if child number is hardened
    #[frb]
    pub fn is_hardened(&self) -> bool {
        matches!(self.inner.child_number(), ChildNumber::Hardened(_))
    }

    /// Get fingerprint of this key
    #[frb]
    pub fn fingerprint(&self) -> Vec<u8> {
        self.inner.fingerprint().to_vec()
    }

    /// Derive a single child key
    #[frb]
    pub fn derive_child(&self, index: u32, hardened: bool) -> Result<Self, String> {
        let child_num = if hardened {
            ChildNumber::Hardened(index)
        } else {
            ChildNumber::Normal(index)
        };

        let child = self.inner.derive_child(child_num)
            .map_err(|e| e.to_string())?;
        
        Ok(Self { inner: child })
    }

    /// Derive using a path string (e.g., "m/44'/0'/0'/0/0")
    #[frb]
    pub fn derive_path(&self, path: String) -> Result<Self, String> {
        let derivation_path = DerivationPath::from_str(&path)
            .map_err(|e| e.to_string())?;
        
        let derived = self.inner.derive_path(&derivation_path)
            .map_err(|e| e.to_string())?;
        
        Ok(Self { inner: derived })
    }

    /// Convert to extended public key
    #[frb]
    pub fn to_extended_public_key(&self) -> ExtendedPublicKey {
        ExtendedPublicKey {
            inner: self.inner.to_extended_public_key(),
        }
    }

    /// Serialize to string (xprv... format)
    #[frb]
    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }

    /// Parse from string
    #[frb]
    pub fn from_string(s: String) -> Result<Self, String> {
        let key = RustExtendedPrivateKey::from_str(&s)
            .map_err(|e| e.to_string())?;
        Ok(Self { inner: key })
    }
}

/// Flutter wrapper for ExtendedPublicKey
#[frb]
pub struct ExtendedPublicKey {
    inner: RustExtendedPublicKey,
}

#[frb]
impl ExtendedPublicKey {
    /// Get the depth in derivation tree
    #[frb]
    pub fn depth(&self) -> u8 {
        self.inner.depth()
    }

    /// Get fingerprint
    #[frb]
    pub fn fingerprint(&self) -> Vec<u8> {
        self.inner.fingerprint().to_vec()
    }

    /// Derive a child public key (non-hardened only)
    #[frb]
    pub fn derive_child(&self, index: u32) -> Result<Self, String> {
        let child = self.inner.derive_child(ChildNumber::Normal(index))
            .map_err(|e| e.to_string())?;
        Ok(Self { inner: child })
    }

    /// Serialize to string (xpub... format)
    #[frb]
    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }

    /// Parse from string
    #[frb]
    pub fn from_string(s: String) -> Result<Self, String> {
        let key = RustExtendedPublicKey::from_str(&s)
            .map_err(|e| e.to_string())?;
        Ok(Self { inner: key })
    }
}

/// Flutter wrapper for Mnemonic
#[frb]
pub struct Mnemonic {
    inner: RustMnemonic,
}

#[frb]
impl Mnemonic {
    /// Generate a new mnemonic
    #[frb]
    pub fn generate(word_count: u32) -> Result<Self, String> {
        let count = match word_count {
            12 => WordCount::Twelve,
            15 => WordCount::Fifteen,
            18 => WordCount::Eighteen,
            21 => WordCount::TwentyOne,
            24 => WordCount::TwentyFour,
            _ => return Err("Invalid word count".to_string()),
        };

        let mnemonic = RustMnemonic::generate(count, Language::English)
            .map_err(|e| e.to_string())?;
        
        Ok(Self { inner: mnemonic })
    }

    /// Parse from phrase
    #[frb]
    pub fn from_phrase(phrase: String) -> Result<Self, String> {
        let mnemonic = RustMnemonic::from_phrase(&phrase, Language::English)
            .map_err(|e| e.to_string())?;
        Ok(Self { inner: mnemonic })
    }

    /// Get the mnemonic phrase as string
    #[frb]
    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }

    /// Get word count
    #[frb]
    pub fn word_count(&self) -> u32 {
        self.inner.to_string().split_whitespace().count() as u32
    }

    /// Validate the mnemonic
    #[frb]
    pub fn is_valid(&self) -> bool {
        true // If we constructed it, it's valid
    }
}

/// Network type enum
#[frb]
#[derive(Debug, Clone, Copy)]
pub enum NetworkType {
    BitcoinMainnet,
    BitcoinTestnet,
}

impl From<NetworkType> for Network {
    fn from(nt: NetworkType) -> Self {
        match nt {
            NetworkType::BitcoinMainnet => Network::BitcoinMainnet,
            NetworkType::BitcoinTestnet => Network::BitcoinTestnet,
        }
    }
}

impl From<Network> for NetworkType {
    fn from(n: Network) -> Self {
        match n {
            Network::BitcoinMainnet => NetworkType::BitcoinMainnet,
            Network::BitcoinTestnet => NetworkType::BitcoinTestnet,
        }
    }
}
```

---

## Flutter Usage Example

With the wrapper structs, your Flutter code becomes object-oriented:

```dart
// Generate mnemonic
final mnemonic = await Mnemonic.generate(wordCount: 12);
print('Mnemonic: ${await mnemonic.toPhrase()}');
print('Word count: ${await mnemonic.wordCount()}');

// Create master key from mnemonic
final masterKey = await ExtendedPrivateKey.fromMnemonic(
  mnemonic: mnemonic,
  passphrase: null,
  network: NetworkType.BitcoinMainnet,
);

// Access properties
print('Depth: ${await masterKey.depth()}');
print('Network: ${await masterKey.network()}');
print('Fingerprint: ${await masterKey.fingerprint()}');

// Derive child keys - method chaining!
final accountKey = await masterKey.deriveChild(index: 44, hardened: true);
final coinKey = await accountKey.deriveChild(index: 0, hardened: true);
final walletKey = await coinKey.deriveChild(index: 0, hardened: true);

// Or use path derivation
final derived = await masterKey.derivePath(path: "m/44'/0'/0'");
print('Account depth: ${await derived.depth()}'); // 3

// Get public key
final pubKey = await masterKey.toExtendedPublicKey();
print('Public key: ${await pubKey.toExtendedString()}');

// Derive non-hardened child from public key
final addressPubKey = await pubKey.deriveChild(index: 0);
```

---

## Comparison

### ❌ Function-Only Approach (Current Guide)

```dart
// Generate and pass strings everywhere
final mnemonicStr = await generateMnemonic(wordCount: 12);
final masterKeyStr = await createMasterKey(
  mnemonic: mnemonicStr,
  passphrase: null,
  network: NetworkType.BitcoinMainnet,
);

// No way to call methods on masterKey
// Must use wrapper functions with strings
final childKeyStr = await deriveKey(
  extendedKey: masterKeyStr,
  derivationPath: "m/44'/0'/0'",
);

// No type safety, just strings
```

### ✅ Struct Wrapper Approach

```dart
// Objects with methods
final mnemonic = await Mnemonic.generate(wordCount: 12);
final masterKey = await ExtendedPrivateKey.fromMnemonic(
  mnemonic: mnemonic,  // Type-safe!
  passphrase: null,
  network: NetworkType.BitcoinMainnet,
);

// Direct method calls
final depth = await masterKey.depth();
final child = await masterKey.deriveChild(index: 0, hardened: true);
```

---

## Key Differences

| Feature | Function-Only | Struct Wrapper |
|---------|--------------|----------------|
| **Type Safety** | ❌ Strings only | ✅ Strongly typed |
| **Method Calls** | ❌ Must use wrapper functions | ✅ Direct `.method()` calls |
| **Intellisense** | ❌ Limited | ✅ Full IDE support |
| **Error Prone** | ⚠️ Easy to pass wrong strings | ✅ Type system catches errors |
| **API Feel** | Procedural | Object-Oriented |

---

## Recommendation

**Use the Struct Wrapper approach** for your production app because:

1. ✅ **Type Safety** - Compiler catches errors
2. ✅ **Better DX** - Flutter developers expect OOP
3. ✅ **Maintainability** - Easier to refactor
4. ✅ **Complete API** - Access all struct methods
5. ✅ **IDE Support** - Better autocomplete

---

## Implementation Steps

1. Replace the `bridge.rs` content in the main guide with wrapper structs
2. Keep the `inner` field private (encapsulation)
3. Expose only the methods you want Flutter to use
4. Use `Result<T, String>` for error handling
5. Convert between Rust types and Flutter-friendly types (Vec<u8>, String, etc.)

---

## Important Notes

- **Cloning**: Wrapper pattern requires cloning the inner struct for some operations
- **Memory**: Objects stay in memory until Dart garbage collects them
- **Async**: All methods become `async` in Dart
- **Conversions**: May need to convert complex Rust types to simpler ones (like arrays to Vec)
