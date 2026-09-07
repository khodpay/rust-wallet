# Library Organization for Git

## 📚 Workspace Crates

| Crate | Path | Description |
|---|---|---|
| `khodpay-bip39` | `crates/bip39` | BIP-39 mnemonic generation, validation, and seed derivation |
| `khodpay-bip32` | `crates/bip32` | BIP-32 HD key derivation (extended private/public keys, derivation paths) |
| `khodpay-bip44` | `crates/bip44` | BIP-44 multi-account wallet (coin types, account/chain/address derivation) |
| `khodpay-signing` | `crates/khodpay-signing` | EVM transaction signing, EIP-1559, EIP-712, ERC-4337 (BIP-44 key path) |
| `khodpay-mpc-tss` | `crates/mpc-tss` | 2-of-2 threshold ECDSA engine (CGGMP21/secp256k1): DKG, signing, resharing. No mnemonic involved; secret key is split across device and server — never assembled in full |
| `khodpay-flutter-bridge` | `crates/flutter_bridge` | `flutter_rust_bridge` bindings exposing all of the above to Dart/Flutter |

---

## 🎯 Overview

After building, libraries are automatically organized into `build/libs/` with intermediate build artifacts removed. This keeps the repository clean while providing all necessary files for Flutter integration.

---

## 📁 Directory Structure

```
build/
├── dart/                           # Dart bindings (commit these)
│   ├── bridge.dart
│   ├── frb_generated.dart
│   ├── frb_generated.io.dart
│   └── frb_generated.web.dart
│
└── libs/                          # Organized libraries (commit these)
    ├── macos/                     # ~25 MB
    │   ├── libkhodpay_flutter_bridge.dylib  (400 KB)
    │   └── libkhodpay_flutter_bridge.a      (25 MB)
    │
    ├── ios/                       # ~50 MB
    │   ├── libkhodpay_flutter_bridge_ios.a    (device)
    │   └── libkhodpay_flutter_bridge_iossim.a (simulator)
    │
    └── android/                   # ~1.6 MB
        ├── arm64-v8a/
        │   └── libkhodpay_flutter_bridge.so  (655 KB)
        ├── armeabi-v7a/
        │   └── libkhodpay_flutter_bridge.so  (364 KB)
        └── x86_64/
            └── libkhodpay_flutter_bridge.so  (602 KB)
```

**Total Size: ~77 MB** (down from ~200+ MB of intermediate artifacts)

---

## 🚀 Automatic Organization

The `./scripts/build_all.sh` script automatically:

1. ✅ **Generates** Flutter Rust Bridge code
2. ✅ **Compiles** all platforms in parallel
3. ✅ **Organizes** libraries into clean structure
4. ✅ **Removes** large intermediate build artifacts (~150+ MB saved)

---

## 📦 What Gets Committed to Git

### ✅ **Keep (Commit These)**
- `build/dart/` - Dart bindings
- `build/libs/` - Organized native libraries
- All source code and scripts

### ❌ **Ignore (Removed Automatically)**
- `build/rust/release/` - Intermediate artifacts
- `build/rust/debug/` - Debug artifacts
- `build/rust/aarch64-*/` - Target-specific build dirs
- `build/rust/armv7-*/` - Target-specific build dirs
- `build/rust/x86_64-*/` - Target-specific build dirs
- `build/rust/*.log` - Build logs

These are configured in `.gitignore`.

---

## 🔧 Manual Organization

If you need to organize libraries manually:

```bash
./scripts/organize_libs.sh
```

This script:
- Copies libraries from build artifacts to `build/libs/`
- Organizes by platform (macOS, iOS, Android)
- Removes all intermediate build files
- Shows final structure and sizes

---

## 🎯 Flutter Integration

Copy from the organized structure:

### macOS
```bash
cp build/libs/macos/libkhodpay_flutter_bridge.dylib <flutter-app>/macos/
```

### iOS
```bash
# Device
cp build/libs/ios/libkhodpay_flutter_bridge_ios.a <flutter-app>/ios/Frameworks/

# Simulator (optional)
cp build/libs/ios/libkhodpay_flutter_bridge_iossim.a <flutter-app>/ios/Frameworks/
```

### Android
```bash
# Copy all at once
cp -r build/libs/android/* <flutter-app>/android/app/src/main/jniLibs/
```

---

## 📊 Size Comparison

| Item | Before | After | Saved |
|------|--------|-------|-------|
| **Build artifacts** | ~200 MB | 0 MB | ~200 MB |
| **Libraries** | (scattered) | 77 MB | - |
| **Total committed** | ~200 MB | **77 MB** | **61% smaller** |

---

## 🔍 Verification

Check what's ready for commit:

```bash
# See organized libraries
ls -lh build/libs/*/

# Check sizes
du -sh build/libs/*

# Verify intermediate artifacts removed
ls build/rust/  # Should only show minimal files
```

---

## ⚠️ Important Notes

1. **Always run** `./scripts/build_all.sh` for complete builds
2. **Don't manually edit** `build/libs/` - it's auto-generated
3. **Commit both** `build/dart/` and `build/libs/` to git
4. **Rebuild** after pulling changes to regenerate artifacts
5. **CI/CD** should run `./scripts/build_all.sh` to generate fresh libs

---

## 🔄 Rebuild Workflow

```bash
# Clean build from scratch
cargo clean
rm -rf build/
./scripts/build_all.sh

# Incremental rebuild
./scripts/build_all.sh  # Automatically organizes
```

---

## 📝 Git Workflow

```bash
# After building
./scripts/build_all.sh

# Check what's changed
git status

# Should see:
# - build/dart/           (Dart bindings)
# - build/libs/          (Organized libraries)
# - Source code changes

# Commit everything
git add build/dart build/libs crates/ scripts/ docs/
git commit -m "feat: Update Flutter bridge libraries"
git push
```

---

**The organized library structure makes it easy to commit necessary files while keeping the repository clean!** 📦✨
