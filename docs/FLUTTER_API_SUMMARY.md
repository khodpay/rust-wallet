# Flutter Rust Bridge API Summary

## Overview

The KhodPay wallet Flutter integration provides **TWO complementary APIs**:

1. **Object-Oriented API** (Struct Wrappers) - Full type-safe access to all Rust structs and their methods
2. **Utility Functions API** (Procedural) - Simple function-based operations with strings

---

## 🎯 Quick Reference

### Object-Oriented API

```dart
// Mnemonic Management
final mnemonic = await Mnemonic.generate(wordCount: 12);
final phrase = await mnemonic.toPhrase();
final wordCount = await mnemonic.wordCount();
final isValid = await mnemonic.isValid();
final loaded = await Mnemonic.fromPhrase(phrase);

// ExtendedPrivateKey Operations
final masterKey = await ExtendedPrivateKey.fromMnemonic(
  mnemonic: mnemonic,
  passphrase: null,
  network: NetworkType.BitcoinMainnet,
);

// Access all methods
final depth = await masterKey.depth();
final network = await masterKey.network();
final fingerprint = await masterKey.fingerprint();
final parentFp = await masterKey.parentFingerprint();
final childIndex = await masterKey.childNumberIndex();
final isHardened = await masterKey.isHardened();

// Derive children
final child = await masterKey.deriveChild(index: 0, hardened: true);
final derived = await masterKey.derivePath(path: "m/44'/0'/0'");

// Convert to public key
final pubKey = await masterKey.toExtendedPublicKey();

// Serialize/deserialize
final xprv = await masterKey.toExtendedString();
final loaded = await ExtendedPrivateKey.fromString(xprv);
final fromSeed = await ExtendedPrivateKey.fromSeed(seedBytes, network);

// ExtendedPublicKey Operations
final xpub = await pubKey.toExtendedString();
final depth = await pubKey.depth();
final fingerprint = await pubKey.fingerprint();
final childPub = await pubKey.deriveChild(index: 0); // Non-hardened only
final derivedPub = await pubKey.derivePath(path: "m/0/0");
```

### Utility Functions API

```dart
// Quick operations with strings
final mnemonicStr = await generateMnemonic(wordCount: 12);
final isValid = await validateMnemonic(mnemonicStr);

final masterKeyStr = await createMasterKey(
  mnemonic: mnemonicStr,
  passphrase: null,
  network: NetworkType.BitcoinMainnet,
);

final derivedStr = await deriveKey(
  extendedKey: masterKeyStr,
  derivationPath: "m/44'/0'/0'",
);

final pubKeyStr = await getPublicKey(extendedPrivateKey: masterKeyStr);
final addressStr = await getAddress(extendedPrivateKey: masterKeyStr, addressIndex: 0);

final result = await createBip44Wallet(
  mnemonic: mnemonicStr,
  passphrase: null,
  accountIndex: 0,
  network: NetworkType.BitcoinMainnet,
);

final status = await healthCheck();
```

---

## 🔑 Key Differences

### Available Methods

**Object-Oriented API gives you access to:**
- ✅ `depth()` - Get key depth in tree
- ✅ `network()` - Get network type
- ✅ `fingerprint()` - Get key fingerprint
- ✅ `parentFingerprint()` - Get parent fingerprint
- ✅ `childNumberIndex()` - Get child index
- ✅ `isHardened()` - Check if hardened
- ✅ `deriveChild()` - Derive single child
- ✅ `derivePath()` - Derive using path
- ✅ `toExtendedPublicKey()` - Convert to public
- ✅ `toExtendedString()` / `fromString()` - Serialize
- ✅ `fromSeed()` / `fromMnemonic()` - Construct

**Utility Functions API:**
- ⚠️ Only the explicitly exported functions
- ⚠️ No direct method access on structs
- ⚠️ Must use wrapper functions for everything

---

## 💡 When to Use Each

### Use OOP API When:
- Building a wallet application
- Need to access multiple properties of keys
- Want IDE autocomplete and type safety
- Performing multiple operations on same key
- Building complex derivation logic

### Use Utility Functions When:
- Quick one-off operations
- Working with stored string data
- Simple validation tasks
- Performance-critical paths
- Building CLI tools or scripts

### Mix Both:
```dart
// Generate with OOP
final mnemonic = await Mnemonic.generate(wordCount: 12);
final phrase = await mnemonic.toPhrase();

// Save to storage
await storage.write(key: 'mnemonic', value: phrase);

// Later: Quick validation with utility function
final saved = await storage.read(key: 'mnemonic');
if (!await validateMnemonic(saved!)) {
  throw Exception('Invalid mnemonic');
}

// Then back to OOP for complex operations
final loadedMnemonic = await Mnemonic.fromPhrase(saved!);
final masterKey = await ExtendedPrivateKey.fromMnemonic(
  mnemonic: loadedMnemonic,
  network: NetworkType.BitcoinMainnet,
);
```

---

## 📊 Comparison Table

| Aspect | OOP API | Utility API |
|--------|---------|-------------|
| **Return Types** | Dart objects (`Mnemonic`, `ExtendedPrivateKey`) | Strings (`String`, `bool`) |
| **Method Access** | ✅ All struct methods available | ❌ Only exported functions |
| **Type Safety** | ✅ Compile-time checks | ⚠️ Runtime string validation |
| **IDE Support** | ✅ Full autocomplete | ⚠️ Function signatures only |
| **Memory** | Objects in memory | Minimal (strings) |
| **Ease of Use** | More powerful but complex | Simple and direct |
| **Best For** | Complex apps | Simple tasks |

---

## 🚀 Recommended Pattern for Production

```dart
class WalletService {
  // Use OOP for core wallet logic
  ExtendedPrivateKey? _masterKey;
  
  Future<void> createWallet(String mnemonic) async {
    // Validate with utility function (fast)
    if (!await validateMnemonic(mnemonic)) {
      throw Exception('Invalid mnemonic');
    }
    
    // Create with OOP (type-safe)
    final mnemonicObj = await Mnemonic.fromPhrase(mnemonic);
    _masterKey = await ExtendedPrivateKey.fromMnemonic(
      mnemonic: mnemonicObj,
      network: NetworkType.BitcoinMainnet,
    );
  }
  
  Future<String> getReceiveAddress(int index) async {
    if (_masterKey == null) throw Exception('Wallet not initialized');
    
    // Use OOP for derivation (access to methods)
    final receivePath = await _masterKey!.derivePath(path: "m/44'/0'/0'/0/$index");
    final pubKey = await receivePath.toExtendedPublicKey();
    
    return await pubKey.toExtendedString();
  }
  
  Future<Map<String, dynamic>> getWalletInfo() async {
    if (_masterKey == null) throw Exception('Wallet not initialized');
    
    // OOP gives you easy access to all properties
    return {
      'depth': await _masterKey!.depth(),
      'network': await _masterKey!.network(),
      'fingerprint': await _masterKey!.fingerprint(),
      'is_hardened': await _masterKey!.isHardened(),
    };
  }
  
  Future<void> backup() async {
    if (_masterKey == null) throw Exception('Wallet not initialized');
    
    // Serialize for storage
    final xprv = await _masterKey!.toExtendedString();
    await secureStorage.write(key: 'master_key', value: xprv);
  }
  
  Future<void> restore() async {
    final xprv = await secureStorage.read(key: 'master_key');
    if (xprv == null) throw Exception('No backup found');
    
    // Deserialize back to object
    _masterKey = await ExtendedPrivateKey.fromString(xprv);
  }
}
```

---

## ✅ Summary

- **Both APIs are available** and fully functional
- **Both work together** seamlessly
- **OOP API**: Full access to all Rust struct methods (recommended for apps)
- **Utility API**: Simple functions for quick operations (good for scripts)
- **Choose based on your needs** - or mix both approaches
- **Type safety** is the main advantage of the OOP approach
- **Simplicity** is the main advantage of the utility approach

---

**See the full guide at:** `docs/FLUTTER_INTEGRATION_GUIDE.md`
