# Flutter Integration Guide

This guide shows you how to integrate the KhodPay Wallet Rust libraries into your Flutter project and use them.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Project Setup](#project-setup)
3. [Building the Libraries](#building-the-libraries)
4. [Copying Libraries to Flutter](#copying-libraries-to-flutter)
5. [Generating Dart Bindings](#generating-dart-bindings)
6. [Flutter Project Configuration](#flutter-project-configuration)
7. [Usage Examples](#usage-examples)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools

1. **Rust toolchain** (1.81 or later)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Flutter SDK** (3.0 or later)
   ```bash
   # Follow instructions at https://flutter.dev/docs/get-started/install
   ```

3. **flutter_rust_bridge_codegen**
   ```bash
   cargo install flutter_rust_bridge_codegen
   ```

4. **Rust targets** (for cross-platform builds)
   ```bash
   cd /path/to/khodpay-wallet
   ./scripts/setup_targets.sh
   ```

5. **Android NDK** (for Android builds)
   - Install via Android Studio → SDK Manager → SDK Tools → NDK
   - Set environment variable:
     ```bash
     export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/<version>
     ```

---

## Project Setup

### Step 1: Create or Open Your Flutter Project

```bash
# Create a new Flutter project
flutter create my_wallet_app
cd my_wallet_app

# Or open your existing project
cd /path/to/your/flutter/project
```

### Step 2: Add Required Dependencies

Edit your `pubspec.yaml`:

```yaml
name: my_wallet_app
description: A cryptocurrency wallet app

environment:
  sdk: '>=3.0.0 <4.0.0'

dependencies:
  flutter:
    sdk: flutter
  
  # Flutter Rust Bridge runtime
  flutter_rust_bridge: ^2.11.1
  
  # Required for FFI
  ffi: ^2.1.0

dev_dependencies:
  flutter_test:
    sdk: flutter
  
  # Required for code generation
  freezed: ^2.4.5
  build_runner: ^2.4.6
  
  flutter_lints: ^2.0.0
```

Install dependencies:

```bash
flutter pub get
```

---

## Building the Libraries

### Step 1: Navigate to the Rust Project

```bash
cd /path/to/khodpay-wallet
```

### Step 2: Build for Your Target Platforms

#### Option A: Build for All Platforms

```bash
./scripts/build_rust.sh release all
```

This builds for:
- macOS/Desktop
- iOS (device and simulator)
- Android (ARM64, ARMv7, x86_64)

#### Option B: Build for Specific Platforms

```bash
# macOS only
./scripts/build_rust.sh release macos

# iOS only
./scripts/build_rust.sh release ios

# Android only
./scripts/build_rust.sh release android
```

### Step 3: Verify Build Output

Check that libraries were created:

```bash
ls -lh build/rust/release/
ls -lh build/rust/aarch64-apple-ios/release/
ls -lh build/rust/aarch64-linux-android/release/
```

---

## Copying Libraries to Flutter

### macOS (Desktop)

```bash
# Create directory if it doesn't exist
mkdir -p /path/to/flutter/project/macos/Frameworks

# Copy the dylib
cp build/rust/release/libkhodpay_flutter_bridge.dylib \
   /path/to/flutter/project/macos/Frameworks/
```

### iOS

```bash
# Create directory structure
mkdir -p /path/to/flutter/project/ios/Frameworks

# Copy iOS device library
cp build/rust/aarch64-apple-ios/release/libkhodpay_flutter_bridge.a \
   /path/to/flutter/project/ios/Frameworks/libkhodpay_flutter_bridge_ios.a

# Copy iOS simulator library
cp build/rust/aarch64-apple-ios-sim/release/libkhodpay_flutter_bridge.a \
   /path/to/flutter/project/ios/Frameworks/libkhodpay_flutter_bridge_sim.a
```

For iOS, you may need to create a universal framework:

```bash
cd /path/to/flutter/project/ios/Frameworks

# Create universal library (device + simulator)
lipo -create \
  libkhodpay_flutter_bridge_ios.a \
  libkhodpay_flutter_bridge_sim.a \
  -output libkhodpay_flutter_bridge.a
```

### Android

```bash
# Create jniLibs directory structure
mkdir -p /path/to/flutter/project/android/app/src/main/jniLibs/arm64-v8a
mkdir -p /path/to/flutter/project/android/app/src/main/jniLibs/armeabi-v7a
mkdir -p /path/to/flutter/project/android/app/src/main/jniLibs/x86_64

# Copy Android libraries
cp build/rust/aarch64-linux-android/release/libkhodpay_flutter_bridge.so \
   /path/to/flutter/project/android/app/src/main/jniLibs/arm64-v8a/

cp build/rust/armv7-linux-androideabi/release/libkhodpay_flutter_bridge.so \
   /path/to/flutter/project/android/app/src/main/jniLibs/armeabi-v7a/

cp build/rust/x86_64-linux-android/release/libkhodpay_flutter_bridge.so \
   /path/to/flutter/project/android/app/src/main/jniLibs/x86_64/
```

---

## Generating Dart Bindings

### Step 1: Copy Bridge Source to Flutter Project

```bash
# Create lib/rust directory in your Flutter project
mkdir -p /path/to/flutter/project/lib/rust

# This will be where generated Dart code goes
```

### Step 2: Generate Bindings

From the Rust project directory:

```bash
cd /path/to/khodpay-wallet

# Generate bindings
flutter_rust_bridge_codegen generate \
  --rust-input "crate::bridge" \
  --rust-root "crates/flutter_bridge" \
  --dart-output "/path/to/flutter/project/lib/rust/" \
  --rust-output "crates/flutter_bridge/src/bridge_generated.rs" \
  --dart-entrypoint-class-name "RustLib" \
  --no-add-mod-to-lib
```

Or use the provided script (after updating the output path):

```bash
# Edit scripts/generate_bridge.sh to point to your Flutter project
# Then run:
./scripts/generate_bridge.sh
```

### Step 3: Verify Generated Files

Check that these files were created in your Flutter project:

```bash
ls /path/to/flutter/project/lib/rust/
# Should see: bridge_generated.dart, bridge_generated.freezed.dart, etc.
```

---

## Flutter Project Configuration

### iOS Configuration

Edit `ios/Runner.xcodeproj/project.pbxproj` or use Xcode:

1. Open the project in Xcode
2. Select the Runner target
3. Go to "Build Phases" → "Link Binary With Libraries"
4. Add `libkhodpay_flutter_bridge.a`
5. Set "Minimum Deployment Target" to iOS 12.0 or later

Or edit `ios/Podfile`:

```ruby
platform :ios, '12.0'

# Add this after the target 'Runner' do line
post_install do |installer|
  installer.pods_project.targets.each do |target|
    flutter_additional_ios_build_settings(target)
    
    target.build_configurations.each do |config|
      # Add library search path
      config.build_settings['LIBRARY_SEARCH_PATHS'] ||= ['$(inherited)']
      config.build_settings['LIBRARY_SEARCH_PATHS'] << '$(PROJECT_DIR)/Frameworks'
    end
  end
end
```

### Android Configuration

Edit `android/app/build.gradle`:

```gradle
android {
    // ... existing config ...
    
    defaultConfig {
        // ... existing config ...
        
        ndk {
            // Specify ABIs you want to support
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86_64'
        }
    }
    
    // Add this if not present
    sourceSets {
        main {
            jniLibs.srcDirs = ['src/main/jniLibs']
        }
    }
}
```

### macOS Configuration

Edit `macos/Runner/DebugProfile.entitlements` and `macos/Runner/Release.entitlements`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Add any required entitlements -->
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
</dict>
</plist>
```

---

## Usage Examples

### Initialize the Library

Create a file `lib/rust/rust_bridge.dart`:

```dart
import 'rust/bridge_generated.dart';

class RustBridge {
  static RustLib? _instance;
  
  static Future<RustLib> get instance async {
    if (_instance == null) {
      _instance = await RustLib.init();
    }
    return _instance!;
  }
}
```

### Example 1: Generate Mnemonic

```dart
import 'package:flutter/material.dart';
import 'rust/rust_bridge.dart';

class GenerateMnemonicScreen extends StatefulWidget {
  @override
  _GenerateMnemonicScreenState createState() => _GenerateMnemonicScreenState();
}

class _GenerateMnemonicScreenState extends State<GenerateMnemonicScreen> {
  String? _mnemonic;
  bool _isLoading = false;

  Future<void> _generateMnemonic() async {
    setState(() => _isLoading = true);
    
    try {
      final rustLib = await RustBridge.instance;
      
      // Generate 12-word mnemonic
      final mnemonic = await rustLib.generateMnemonic(wordCount: 12);
      
      setState(() {
        _mnemonic = mnemonic;
        _isLoading = false;
      });
    } catch (e) {
      setState(() => _isLoading = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error: $e')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Generate Mnemonic')),
      body: Padding(
        padding: EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            ElevatedButton(
              onPressed: _isLoading ? null : _generateMnemonic,
              child: _isLoading
                  ? CircularProgressIndicator()
                  : Text('Generate Mnemonic'),
            ),
            SizedBox(height: 20),
            if (_mnemonic != null)
              Card(
                child: Padding(
                  padding: EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Your Mnemonic:',
                        style: TextStyle(fontWeight: FontWeight.bold),
                      ),
                      SizedBox(height: 8),
                      Text(
                        _mnemonic!,
                        style: TextStyle(fontSize: 16),
                      ),
                    ],
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
```

### Example 2: Create BIP44 Wallet

```dart
import 'package:flutter/material.dart';
import 'rust/rust_bridge.dart';
import 'rust/bridge_generated.dart';

class CreateWalletScreen extends StatefulWidget {
  @override
  _CreateWalletScreenState createState() => _CreateWalletScreenState();
}

class _CreateWalletScreenState extends State<CreateWalletScreen> {
  final _mnemonicController = TextEditingController();
  final _passphraseController = TextEditingController();
  String? _accountKey;
  bool _isLoading = false;

  Future<void> _createWallet() async {
    setState(() => _isLoading = true);
    
    try {
      final rustLib = await RustBridge.instance;
      
      // Create BIP44 wallet
      final wallet = await Bip44Wallet.fromMnemonic(
        mnemonic: _mnemonicController.text,
        passphrase: _passphraseController.text.isEmpty 
            ? null 
            : _passphraseController.text,
        network: NetworkType.BitcoinMainnet,
      );
      
      // Get Bitcoin account
      final account = await wallet.getAccount(
        purpose: PurposeType.BIP84,  // Native SegWit
        coinType: CoinType.Bitcoin,
        accountIndex: 0,
      );
      
      setState(() {
        _accountKey = account.accountKey;
        _isLoading = false;
      });
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Wallet created successfully!')),
      );
    } catch (e) {
      setState(() => _isLoading = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error: $e')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Create Wallet')),
      body: SingleChildScrollView(
        padding: EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              controller: _mnemonicController,
              decoration: InputDecoration(
                labelText: 'Mnemonic Phrase',
                hintText: 'Enter 12 or 24 words',
                border: OutlineInputBorder(),
              ),
              maxLines: 3,
            ),
            SizedBox(height: 16),
            TextField(
              controller: _passphraseController,
              decoration: InputDecoration(
                labelText: 'Passphrase (optional)',
                border: OutlineInputBorder(),
              ),
              obscureText: true,
            ),
            SizedBox(height: 20),
            ElevatedButton(
              onPressed: _isLoading ? null : _createWallet,
              child: _isLoading
                  ? CircularProgressIndicator()
                  : Text('Create Wallet'),
            ),
            if (_accountKey != null) ...[
              SizedBox(height: 20),
              Card(
                child: Padding(
                  padding: EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Account Key:',
                        style: TextStyle(fontWeight: FontWeight.bold),
                      ),
                      SizedBox(height: 8),
                      Text(
                        _accountKey!,
                        style: TextStyle(fontSize: 12),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
  
  @override
  void dispose() {
    _mnemonicController.dispose();
    _passphraseController.dispose();
    super.dispose();
  }
}
```

### Example 3: Derive Addresses

```dart
import 'package:flutter/material.dart';
import 'rust/rust_bridge.dart';
import 'rust/bridge_generated.dart';

class DeriveAddressesScreen extends StatefulWidget {
  final Bip44Account account;
  
  const DeriveAddressesScreen({required this.account});

  @override
  _DeriveAddressesScreenState createState() => _DeriveAddressesScreenState();
}

class _DeriveAddressesScreenState extends State<DeriveAddressesScreen> {
  List<String> _addresses = [];
  bool _isLoading = false;

  Future<void> _deriveAddresses() async {
    setState(() => _isLoading = true);
    
    try {
      final rustLib = await RustBridge.instance;
      
      // Derive first 10 receiving addresses
      final addresses = await widget.account.deriveAddressRange(
        chain: ChainType.External,
        start: 0,
        count: 10,
      );
      
      setState(() {
        _addresses = addresses;
        _isLoading = false;
      });
    } catch (e) {
      setState(() => _isLoading = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error: $e')),
      );
    }
  }

  @override
  void initState() {
    super.initState();
    _deriveAddresses();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Addresses')),
      body: _isLoading
          ? Center(child: CircularProgressIndicator())
          : ListView.builder(
              itemCount: _addresses.length,
              itemBuilder: (context, index) {
                return ListTile(
                  leading: CircleAvatar(child: Text('${index + 1}')),
                  title: Text(
                    _addresses[index],
                    style: TextStyle(fontSize: 12, fontFamily: 'monospace'),
                  ),
                  trailing: IconButton(
                    icon: Icon(Icons.copy),
                    onPressed: () {
                      // Copy to clipboard
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text('Address copied!')),
                      );
                    },
                  ),
                );
              },
            ),
    );
  }
}
```

### Example 4: Multi-Coin Wallet

```dart
import 'package:flutter/material.dart';
import 'rust/rust_bridge.dart';
import 'rust/bridge_generated.dart';

class MultiCoinWalletScreen extends StatefulWidget {
  final String mnemonic;
  
  const MultiCoinWalletScreen({required this.mnemonic});

  @override
  _MultiCoinWalletScreenState createState() => _MultiCoinWalletScreenState();
}

class _MultiCoinWalletScreenState extends State<MultiCoinWalletScreen> {
  Map<String, Bip44Account> _accounts = {};
  bool _isLoading = false;

  Future<void> _setupWallet() async {
    setState(() => _isLoading = true);
    
    try {
      final rustLib = await RustBridge.instance;
      
      // Create wallet
      final wallet = await Bip44Wallet.fromMnemonic(
        mnemonic: widget.mnemonic,
        passphrase: null,
        network: NetworkType.BitcoinMainnet,
      );
      
      // Get accounts for different coins
      final btcAccount = await wallet.getAccount(
        purpose: PurposeType.BIP84,
        coinType: CoinType.Bitcoin,
        accountIndex: 0,
      );
      
      final ethAccount = await wallet.getAccount(
        purpose: PurposeType.BIP44,
        coinType: CoinType.Ethereum,
        accountIndex: 0,
      );
      
      final ltcAccount = await wallet.getAccount(
        purpose: PurposeType.BIP84,
        coinType: CoinType.Litecoin,
        accountIndex: 0,
      );
      
      setState(() {
        _accounts = {
          'Bitcoin': btcAccount,
          'Ethereum': ethAccount,
          'Litecoin': ltcAccount,
        };
        _isLoading = false;
      });
    } catch (e) {
      setState(() => _isLoading = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error: $e')),
      );
    }
  }

  @override
  void initState() {
    super.initState();
    _setupWallet();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Multi-Coin Wallet')),
      body: _isLoading
          ? Center(child: CircularProgressIndicator())
          : ListView(
              children: _accounts.entries.map((entry) {
                return Card(
                  margin: EdgeInsets.all(8),
                  child: ListTile(
                    leading: Icon(Icons.account_balance_wallet),
                    title: Text(entry.key),
                    subtitle: Text(
                      'Account ${entry.value.accountIndex}',
                      style: TextStyle(fontSize: 12),
                    ),
                    trailing: Icon(Icons.arrow_forward_ios),
                    onTap: () {
                      Navigator.push(
                        context,
                        MaterialPageRoute(
                          builder: (context) => DeriveAddressesScreen(
                            account: entry.value,
                          ),
                        ),
                      );
                    },
                  ),
                );
              }).toList(),
            ),
    );
  }
}
```

### Example 5: Validate Mnemonic

```dart
import 'package:flutter/material.dart';
import 'rust/rust_bridge.dart';

class ValidateMnemonicScreen extends StatefulWidget {
  @override
  _ValidateMnemonicScreenState createState() => _ValidateMnemonicScreenState();
}

class _ValidateMnemonicScreenState extends State<ValidateMnemonicScreen> {
  final _controller = TextEditingController();
  bool? _isValid;

  Future<void> _validateMnemonic() async {
    try {
      final rustLib = await RustBridge.instance;
      
      final isValid = await rustLib.validateMnemonic(
        phrase: _controller.text,
      );
      
      setState(() => _isValid = isValid);
    } catch (e) {
      setState(() => _isValid = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Validate Mnemonic')),
      body: Padding(
        padding: EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              controller: _controller,
              decoration: InputDecoration(
                labelText: 'Mnemonic Phrase',
                border: OutlineInputBorder(),
              ),
              maxLines: 3,
              onChanged: (_) => setState(() => _isValid = null),
            ),
            SizedBox(height: 16),
            ElevatedButton(
              onPressed: _validateMnemonic,
              child: Text('Validate'),
            ),
            if (_isValid != null) ...[
              SizedBox(height: 20),
              Card(
                color: _isValid! ? Colors.green[100] : Colors.red[100],
                child: Padding(
                  padding: EdgeInsets.all(16),
                  child: Row(
                    children: [
                      Icon(
                        _isValid! ? Icons.check_circle : Icons.error,
                        color: _isValid! ? Colors.green : Colors.red,
                      ),
                      SizedBox(width: 8),
                      Text(
                        _isValid! ? 'Valid Mnemonic' : 'Invalid Mnemonic',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          color: _isValid! ? Colors.green[900] : Colors.red[900],
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
  
  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }
}
```

---

## Troubleshooting

### Common Issues

#### 1. "Library not found" on iOS

**Solution:**
- Verify the library is in `ios/Frameworks/`
- Check Xcode build settings for library search paths
- Clean and rebuild: `flutter clean && flutter pub get`

#### 2. "UnsatisfiedLinkError" on Android

**Solution:**
- Verify `.so` files are in correct `jniLibs` folders
- Check ABI filters in `build.gradle`
- Ensure library names match exactly

#### 3. "Symbol not found" on macOS

**Solution:**
- Verify `.dylib` is in `macos/Frameworks/`
- Check code signing settings
- Rebuild with: `flutter build macos`

#### 4. Dart bindings not generated

**Solution:**
- Ensure `freezed` is in `dev_dependencies`
- Run: `flutter pub get`
- Regenerate bindings with the codegen command

#### 5. Build fails with "cargo not found"

**Solution:**
- Ensure Rust is installed and in PATH
- Restart terminal/IDE after installing Rust
- Verify: `cargo --version`

### Debug Tips

1. **Enable verbose logging:**
   ```bash
   flutter run -v
   ```

2. **Check library loading:**
   ```dart
   try {
     final rustLib = await RustLib.init();
     print('Library loaded successfully');
   } catch (e) {
     print('Failed to load library: $e');
   }
   ```

3. **Verify library architecture:**
   ```bash
   # macOS
   file macos/Frameworks/libkhodpay_flutter_bridge.dylib
   
   # iOS
   lipo -info ios/Frameworks/libkhodpay_flutter_bridge.a
   
   # Android
   file android/app/src/main/jniLibs/arm64-v8a/libkhodpay_flutter_bridge.so
   ```

---

## Best Practices

### Security

1. **Never log sensitive data:**
   ```dart
   // DON'T do this:
   print('Mnemonic: $mnemonic');
   
   // DO this:
   print('Mnemonic generated successfully');
   ```

2. **Use secure storage:**
   ```dart
   // Use flutter_secure_storage for sensitive data
   import 'package:flutter_secure_storage/flutter_secure_storage.dart';
   
   final storage = FlutterSecureStorage();
   await storage.write(key: 'mnemonic', value: mnemonic);
   ```

3. **Clear sensitive data:**
   ```dart
   @override
   void dispose() {
     _mnemonicController.clear();
     _passphraseController.clear();
     super.dispose();
   }
   ```

### Performance

1. **Initialize once:**
   ```dart
   // Use singleton pattern for RustLib
   class RustBridge {
     static RustLib? _instance;
     static Future<RustLib> get instance async {
       _instance ??= await RustLib.init();
       return _instance!;
     }
   }
   ```

2. **Use async/await properly:**
   ```dart
   // Good: Non-blocking UI
   Future<void> _generateMnemonic() async {
     setState(() => _isLoading = true);
     try {
       final mnemonic = await rustLib.generateMnemonic(wordCount: 12);
       setState(() {
         _mnemonic = mnemonic;
         _isLoading = false;
       });
     } catch (e) {
       setState(() => _isLoading = false);
       // Handle error
     }
   }
   ```

3. **Cache derived data:**
   ```dart
   // Cache addresses instead of re-deriving
   final _addressCache = <int, String>{};
   
   Future<String> getAddress(int index) async {
     if (_addressCache.containsKey(index)) {
       return _addressCache[index]!;
     }
     final address = await account.deriveExternal(index: index);
     _addressCache[index] = address;
     return address;
   }
   ```

---

## Additional Resources

- [BIP32 Integration Guide](./BIP32_INTEGRATION.md)
- [BIP39 Integration Guide](./BIP39_INTEGRATION.md)
- [BIP44 Integration Guide](./BIP44_INTEGRATION.md)
- [Flutter Rust Bridge Documentation](https://cjycode.com/flutter_rust_bridge/)
- [Flutter Official Documentation](https://flutter.dev/docs)

---

## Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review the integration guides for each BIP standard
3. Verify your build environment and dependencies
4. Check that libraries are correctly placed in your Flutter project

For more examples and detailed API documentation, refer to the individual BIP integration guides.
