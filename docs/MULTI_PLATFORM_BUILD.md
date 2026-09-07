# Multi-Platform Build System

**Status:** ✅ Configured and Ready

---

## 🎯 What Changed

The build system now **builds for all platforms by default** (macOS, iOS, and Android) instead of just the current platform.

---

## 📦 Supported Platforms

### ✅ macOS/Desktop
- **Library:** `libkhodpay_flutter_bridge.dylib` (dynamic)
- **Library:** `libkhodpay_flutter_bridge.a` (static)
- **Location:** `build/rust/release/`

### ✅ iOS
- **Device:** `aarch64-apple-ios` (ARM64)
- **Simulator:** `aarch64-apple-ios-sim` (Apple Silicon)
- **Simulator:** `x86_64-apple-ios` (Intel)
- **Library:** `libkhodpay_flutter_bridge.a` (static)
- **Location:** `build/rust/{target}/release/`

### ✅ Android
- **ARM64:** `aarch64-linux-android` (modern devices)
- **ARMv7:** `armv7-linux-androideabi` (older devices)
- **x86_64:** `x86_64-linux-android` (emulator)
- **Library:** `libkhodpay_flutter_bridge.so` (shared)
- **Location:** `build/rust/{target}/release/`

---

## 🚀 Quick Start

### 1. First Time Setup
```bash
# Install all required Rust targets
./scripts/setup_targets.sh
```

**Note:** For Android builds, you also need:
- Android Studio installed
- Android NDK installed (via SDK Manager)
- Environment variable set:
  ```bash
  export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/<version>
  ```

### 2. Build for All Platforms
```bash
# Regenerate bridge code and build for all platforms
./scripts/build_all.sh

# Or just build (skip code generation)
./scripts/build_rust.sh
```

### 3. Build for Specific Platform
```bash
./scripts/build_rust.sh release android   # Android only
./scripts/build_rust.sh release ios       # iOS only  
./scripts/build_rust.sh release macos     # macOS only
```

---

## 📁 Build Output Structure

After running `./scripts/build_all.sh`, you'll have:

```
build/rust/
├── release/
│   ├── libkhodpay_flutter_bridge.dylib    # macOS (400 KB)
│   └── libkhodpay_flutter_bridge.a        # macOS (25 MB)
│
├── aarch64-apple-ios/release/
│   └── libkhodpay_flutter_bridge.a        # iOS Device
│
├── aarch64-apple-ios-sim/release/
│   └── libkhodpay_flutter_bridge.a        # iOS Simulator (M1/M2)
│
├── aarch64-linux-android/release/
│   └── libkhodpay_flutter_bridge.so       # Android ARM64
│
├── armv7-linux-androideabi/release/
│   └── libkhodpay_flutter_bridge.so       # Android ARMv7
│
└── x86_64-linux-android/release/
    └── libkhodpay_flutter_bridge.so       # Android Emulator
```

---

## 🔧 Configuration Files Updated

### 1. `.cargo/config.toml`
Added linker configurations for:
- iOS targets (device and simulators)
- Android targets (ARM64, ARMv7, x86_64)

### 2. `scripts/build_rust.sh`
- **Default behavior:** Build for ALL platforms
- **New flags:** Organized platform selection
- **Better output:** Shows all generated libraries

### 3. `scripts/setup_targets.sh` (NEW)
- Installs all required Rust targets
- Checks for Android NDK
- Provides setup instructions

---

## 💡 Usage Examples

### Build Everything
```bash
./scripts/build_all.sh
```
**Output:** All platforms, all architectures

### Build Android Only
```bash
./scripts/build_rust.sh release android
```
**Output:** 
- `aarch64-linux-android/release/libkhodpay_flutter_bridge.so`
- `armv7-linux-androideabi/release/libkhodpay_flutter_bridge.so`
- `x86_64-linux-android/release/libkhodpay_flutter_bridge.so`

### Build iOS Only
```bash
./scripts/build_rust.sh release ios
```
**Output:**
- `aarch64-apple-ios/release/libkhodpay_flutter_bridge.a` (device)
- `aarch64-apple-ios-sim/release/libkhodpay_flutter_bridge.a` (simulator)

### Debug Build (All Platforms)
```bash
./scripts/build_rust.sh debug
```

---

## 📱 Flutter Integration

### macOS
```bash
cp build/rust/release/libkhodpay_flutter_bridge.dylib <flutter-app>/macos/
```

### iOS
```bash
cp build/rust/aarch64-apple-ios/release/libkhodpay_flutter_bridge.a <flutter-app>/ios/Frameworks/
```

### Android
```bash
# ARM64 (most modern devices)
cp build/rust/aarch64-linux-android/release/libkhodpay_flutter_bridge.so \
   <flutter-app>/android/app/src/main/jniLibs/arm64-v8a/

# ARMv7 (older devices)
cp build/rust/armv7-linux-androideabi/release/libkhodpay_flutter_bridge.so \
   <flutter-app>/android/app/src/main/jniLibs/armeabi-v7a/

# x86_64 (emulator)
cp build/rust/x86_64-linux-android/release/libkhodpay_flutter_bridge.so \
   <flutter-app>/android/app/src/main/jniLibs/x86_64/
```

---

## ⚙️ Build Script Options

```bash
./scripts/build_rust.sh [MODE] [PLATFORM]
```

### MODE (optional, default: `release`)
- `release` - Optimized build (~400 KB dylib, ~1-2 MB .so)
- `debug` - Debug build with symbols (larger)

### PLATFORM (optional, default: `all`)
- `all` - Build for all platforms (macOS + iOS + Android)
- `android` - Android only (ARM64 + ARMv7 + x86_64)
- `ios` - iOS only (device + simulator)
- `macos` or `desktop` - macOS only

---

## 🔍 Troubleshooting

### "Android NDK not found"
**Solution:**
1. Install Android Studio
2. Open SDK Manager → SDK Tools
3. Install "NDK (Side by side)"
4. Set environment variable:
   ```bash
   export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/<version>
   # Add to ~/.zshrc or ~/.bashrc to make permanent
   ```

### "Target not installed"
**Solution:**
```bash
./scripts/setup_targets.sh
```

### Build fails for specific platform
**Solution:** Build that platform separately to see detailed error:
```bash
./scripts/build_rust.sh release android  # See Android-specific errors
```

### Libraries too large
**Note:** Static libraries (`.a`) are ~25 MB because they include all dependencies. This is normal. The final app size will be much smaller after linking and optimization.

---

## 📊 Build Times

Typical build times on M1/M2 Mac:

| Build Type | Time | Output Size |
|------------|------|-------------|
| Single platform (release) | ~5-10s | 400 KB - 2 MB |
| All platforms (release) | ~30-60s | ~150 MB total |
| Debug build | ~3-5s | Larger |

---

## ✅ What's Ready

- ✅ All Rust targets configured
- ✅ Build scripts support all platforms
- ✅ Android NDK linker configuration
- ✅ iOS device and simulator support
- ✅ Automated build process
- ✅ Documentation updated

---

## 📖 See Also

- `docs/BUILD_SUCCESS.md` - Complete build guide
- `docs/FLUTTER_INTEGRATION_GUIDE.md` - Flutter integration steps
- `scripts/setup_targets.sh` - Target installation
- `scripts/build_rust.sh` - Build script

---

**The build system is now ready for cross-platform Flutter development!** 🎉
