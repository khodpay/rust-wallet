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

---

## 🔐 MPC Wallet API (Threshold ECDSA)

The MPC session types expose the 2-of-2 CGGMP21 threshold signing engine.
The full private key is **never assembled** on either side.

### Transport contract

Each session type follows the same pattern:
1. Call `create()` to get a session and its `firstRoundPayload`
2. Send `firstRoundPayload` to the KhodPay signer server via gRPC
3. Call `advance(serverPayload)` in a loop until `isComplete == true`

---

### `MpcDkgSession` — distributed key generation

```dart
// Start a DKG ceremony (generates a new MPC wallet address)
final session = await MpcDkgSession.create();
final sessionId = await session.sessionId();       // UUID v4 — forward to server
final payload = await session.firstRoundPayload(); // bytes to send to server

// Drive the ceremony round-by-round
MpcDkgAdvanceResult result;
do {
  final serverBytes = await grpc.sendDkgRound(sessionId, payload);
  result = await session.advance(serverBytes);
} while (!result.isComplete);

// Store the device share in SecureStorageService
await secureStorage.write(
  key: 'mpc_device_share_v1',
  value: base64.encode(result.deviceShare!),
);
final walletAddress = result.walletAddress!; // EIP-55 checksummed
```

#### `MpcDkgSession` methods

| Method | Signature | Description |
|---|---|---|
| `create` | `static Future<MpcDkgSession>` | Creates session, generates first-round payload |
| `sessionId` | `Future<String>` | UUID v4 — forward to server for correlation |
| `firstRoundPayload` | `Future<Uint8List>` | Opaque bytes for the first server round |
| `advance` | `Future<MpcDkgAdvanceResult> Function(Uint8List serverPayload)` | Process one server response |

#### `MpcDkgAdvanceResult` fields

| Field | Type | Description |
|---|---|---|
| `isComplete` | `bool` | `true` when DKG finished |
| `nextPayload` | `Uint8List?` | Forward to server if `!isComplete` |
| `deviceShare` | `Uint8List?` | Opaque share bytes; store as `mpc_device_share_v1` |
| `walletAddress` | `String?` | EIP-55 EVM address derived from joint public key |

---

### `MpcSigningSession` — threshold signing

```dart
// Sign a transaction hash using the stored device share
final shareBytes = base64.decode(
  await secureStorage.read(key: 'mpc_device_share_v1') ?? '',
);
final txHash = keccak256(encodedTransaction); // 32 bytes

final session = await MpcSigningSession.create(
  deviceShare: shareBytes,
  txHash: txHash,
);
final sessionId = await session.sessionId();
final payload = await session.firstRoundPayload();

MpcSigningAdvanceResult result;
do {
  final serverBytes = await grpc.sendSigningRound(sessionId, payload);
  result = await session.advance(serverBytes);
} while (!result.isComplete);

// 65-byte EVM signature: r (32) || s (32) || v (1), v = 0 or 1
final signature = result.signature!;
```

#### `MpcSigningSession` methods

| Method | Signature | Description |
|---|---|---|
| `create` | `static Future<MpcSigningSession> Function(Uint8List deviceShare, Uint8List txHash)` | Validates share + 32-byte hash, generates first payload |
| `sessionId` | `Future<String>` | UUID v4 |
| `firstRoundPayload` | `Future<Uint8List>` | session_id bytes ∥ tx_hash |
| `advance` | `Future<MpcSigningAdvanceResult> Function(Uint8List serverPayload)` | Process one server response; 65-byte payload signals completion |

#### `MpcSigningAdvanceResult` fields

| Field | Type | Description |
|---|---|---|
| `isComplete` | `bool` | `true` when signing finished |
| `nextPayload` | `Uint8List?` | Forward to server if `!isComplete` |
| `signature` | `Uint8List?` | 65-byte EVM signature `r ∥ s ∥ v` |

---

### `MpcReshareSession` — device-loss recovery

```dart
// Issue a new device share (old share is invalidated server-side)
// Server authorises this ceremony via Google ID token (server concern).
final session = await MpcReshareSession.create();
final sessionId = await session.sessionId();
final payload = await session.firstRoundPayload();

MpcReshareAdvanceResult result;
do {
  final serverBytes = await grpc.sendReshareRound(sessionId, payload);
  result = await session.advance(serverBytes);
} while (!result.isComplete);

// Overwrite the old share — do NOT keep both
await secureStorage.write(
  key: 'mpc_device_share_v1',
  value: base64.encode(result.newDeviceShare!),
);
// Wallet address is unchanged after resharing.
```

#### `MpcReshareSession` methods

| Method | Signature | Description |
|---|---|---|
| `create` | `static Future<MpcReshareSession>` | Creates session, generates first-round payload |
| `sessionId` | `Future<String>` | UUID v4 |
| `firstRoundPayload` | `Future<Uint8List>` | Opaque bytes for the first server round |
| `advance` | `Future<MpcReshareAdvanceResult> Function(Uint8List serverPayload)` | Process one server response |

#### `MpcReshareAdvanceResult` fields

| Field | Type | Description |
|---|---|---|
| `isComplete` | `bool` | `true` when resharing finished |
| `nextPayload` | `Uint8List?` | Forward to server if `!isComplete` |
| `newDeviceShare` | `Uint8List?` | New opaque share bytes; overwrite `mpc_device_share_v1` |

---

### SecureStorage key reference

| Key | Written by | Content |
|---|---|---|
| `mpc_device_share_v1` | DKG completion, Reshare completion | Opaque device-side key share bytes |

