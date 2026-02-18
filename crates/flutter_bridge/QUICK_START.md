# Quick Start Guide

## Build Commands

### Build Everything
```bash
./scripts/build_rust.sh release all
./scripts/create_universal_ios.sh release
```

### Build iOS Only
```bash
./scripts/build_rust.sh release ios
./scripts/create_universal_ios.sh release
```

### Build Android Only
```bash
./scripts/build_rust.sh release android
```

### Build macOS Only
```bash
./scripts/build_rust.sh release macos
```

## Verify FFI Symbols

### Check iOS Simulator Library (Intel + ARM64)
```bash
# List all FFI symbols
nm build/libs/ios/libkhodpay_flutter_bridge_sim_universal.a 2>/dev/null | grep " T _frb"

# Check for critical symbol
nm build/libs/ios/libkhodpay_flutter_bridge_sim_universal.a 2>/dev/null | grep "_frb_get_rust_content_hash"

# Verify architectures
lipo -info build/libs/ios/libkhodpay_flutter_bridge_sim_universal.a
```

### Check Android Library
```bash
nm build/rust/aarch64-linux-android/release/libkhodpay_flutter_bridge.so | grep " T frb"
```

### Check macOS Library
```bash
nm build/rust/release/libkhodpay_flutter_bridge.dylib | grep " T _frb"
```

## Library Locations

### iOS
- **Universal Simulator:** `build/libs/ios/libkhodpay_flutter_bridge_sim_universal.a` (x86_64 + ARM64)
- **Device:** `build/libs/ios/libkhodpay_flutter_bridge_device.a` (ARM64)
- **Simulator ARM64:** `build/rust/aarch64-apple-ios-sim/release/libkhodpay_flutter_bridge.a`
- **Simulator x86_64:** `build/rust/x86_64-apple-ios/release/libkhodpay_flutter_bridge.a`

### Android
- **ARM64:** `build/rust/aarch64-linux-android/release/libkhodpay_flutter_bridge.so`
- **ARMv7:** `build/rust/armv7-linux-androideabi/release/libkhodpay_flutter_bridge.so`
- **x86_64:** `build/rust/x86_64-linux-android/release/libkhodpay_flutter_bridge.so`

### macOS
- **Dynamic:** `build/rust/release/libkhodpay_flutter_bridge.dylib`
- **Static:** `build/rust/release/libkhodpay_flutter_bridge.a`

## Copy to Flutter Project

### iOS (Recommended - Universal Library)
```bash
FLUTTER_PROJECT="/path/to/your/flutter/project"
mkdir -p "$FLUTTER_PROJECT/ios/Frameworks"
cp build/libs/ios/libkhodpay_flutter_bridge_sim_universal.a \
   "$FLUTTER_PROJECT/ios/Frameworks/libkhodpay_flutter_bridge.a"
```

### Android
```bash
FLUTTER_PROJECT="/path/to/your/flutter/project"
mkdir -p "$FLUTTER_PROJECT/android/app/src/main/jniLibs"/{arm64-v8a,armeabi-v7a,x86_64}

cp build/rust/aarch64-linux-android/release/libkhodpay_flutter_bridge.so \
   "$FLUTTER_PROJECT/android/app/src/main/jniLibs/arm64-v8a/"

cp build/rust/armv7-linux-androideabi/release/libkhodpay_flutter_bridge.so \
   "$FLUTTER_PROJECT/android/app/src/main/jniLibs/armeabi-v7a/"

cp build/rust/x86_64-linux-android/release/libkhodpay_flutter_bridge.so \
   "$FLUTTER_PROJECT/android/app/src/main/jniLibs/x86_64/"
```

### macOS
```bash
FLUTTER_PROJECT="/path/to/your/flutter/project"
mkdir -p "$FLUTTER_PROJECT/macos/Frameworks"
cp build/rust/release/libkhodpay_flutter_bridge.dylib \
   "$FLUTTER_PROJECT/macos/Frameworks/"
```

## Troubleshooting

### "Library not found" on iOS
1. Verify library exists: `ls -lh build/libs/ios/`
2. Check architectures: `lipo -info build/libs/ios/libkhodpay_flutter_bridge_sim_universal.a`
3. Rebuild: `./scripts/build_rust.sh release ios && ./scripts/create_universal_ios.sh release`

### "Symbol not found" errors
1. Check FFI symbols: `nm build/libs/ios/libkhodpay_flutter_bridge_sim_universal.a | grep frb_get_rust_content_hash`
2. Verify `bridge_generated` module is included in `lib.rs`
3. Rebuild from scratch: `cargo clean && ./scripts/build_rust.sh release all`

### Android "UnsatisfiedLinkError"
1. Verify .so files: `ls -lh build/rust/*/release/*.so`
2. Check ABI filters in `android/app/build.gradle`
3. Ensure library names match exactly

### iOS Simulator on Intel Mac fails
1. Verify x86_64 architecture: `lipo -info build/libs/ios/libkhodpay_flutter_bridge_sim_universal.a`
2. Should show: `x86_64 arm64`
3. If missing, rebuild: `./scripts/build_rust.sh release ios && ./scripts/create_universal_ios.sh release`

## Key Files Modified

1. **`crates/flutter_bridge/src/lib.rs`** - Added `pub mod bridge_generated;`
2. **`scripts/build_rust.sh`** - Added x86_64-apple-ios target support
3. **`scripts/create_universal_ios.sh`** - New script for universal iOS library

## Next Steps

1. Generate Dart bindings (see `FLUTTER_INTEGRATION_GUIDE.md`)
2. Configure your Flutter project for iOS/Android
3. Test on both Intel and Apple Silicon simulators
4. Deploy to devices

For detailed integration instructions, see:
- `FLUTTER_INTEGRATION_GUIDE.md` - Complete Flutter integration guide
- `ISSUE_RESOLVED.md` - Technical details of the fix
