#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}📦 Organizing Libraries for Git Commit${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

BUILD_DIR="build/rust"
LIBS_DIR="build/libs"

# Remove old libs directory if exists
if [ -d "$LIBS_DIR" ]; then
    echo -e "${YELLOW}🗑️  Removing old libs directory...${NC}"
    rm -rf "$LIBS_DIR"
fi

# Create clean directory structure
echo -e "${YELLOW}📁 Creating clean library structure...${NC}"
mkdir -p "$LIBS_DIR/macos"
mkdir -p "$LIBS_DIR/ios"
mkdir -p "$LIBS_DIR/android/arm64-v8a"
mkdir -p "$LIBS_DIR/android/armeabi-v7a"
mkdir -p "$LIBS_DIR/android/x86_64"

# Copy macOS libraries
if [ -f "$BUILD_DIR/release/libkhodpay_flutter_bridge.dylib" ]; then
    cp "$BUILD_DIR/release/libkhodpay_flutter_bridge.dylib" "$LIBS_DIR/macos/"
    echo -e "${GREEN}   ✓ macOS: libkhodpay_flutter_bridge.dylib${NC}"
fi

if [ -f "$BUILD_DIR/release/libkhodpay_flutter_bridge.a" ]; then
    cp "$BUILD_DIR/release/libkhodpay_flutter_bridge.a" "$LIBS_DIR/macos/"
    echo -e "${GREEN}   ✓ macOS: libkhodpay_flutter_bridge.a${NC}"
fi

# Copy iOS libraries
if [ -f "$BUILD_DIR/aarch64-apple-ios/release/libkhodpay_flutter_bridge.a" ]; then
    cp "$BUILD_DIR/aarch64-apple-ios/release/libkhodpay_flutter_bridge.a" "$LIBS_DIR/ios/libkhodpay_flutter_bridge_device.a"
    echo -e "${GREEN}   ✓ iOS Device: libkhodpay_flutter_bridge_device.a${NC}"
fi

if [ -f "$BUILD_DIR/aarch64-apple-ios-sim/release/libkhodpay_flutter_bridge.a" ]; then
    cp "$BUILD_DIR/aarch64-apple-ios-sim/release/libkhodpay_flutter_bridge.a" "$LIBS_DIR/ios/libkhodpay_flutter_bridge_sim_arm64.a"
    echo -e "${GREEN}   ✓ iOS Simulator ARM64: libkhodpay_flutter_bridge_sim_arm64.a${NC}"
fi

if [ -f "$BUILD_DIR/x86_64-apple-ios/release/libkhodpay_flutter_bridge.a" ]; then
    cp "$BUILD_DIR/x86_64-apple-ios/release/libkhodpay_flutter_bridge.a" "$LIBS_DIR/ios/libkhodpay_flutter_bridge_sim_x86_64.a"
    echo -e "${GREEN}   ✓ iOS Simulator x86_64: libkhodpay_flutter_bridge_sim_x86_64.a${NC}"
fi

# Create universal iOS simulator library
if [ -f "$LIBS_DIR/ios/libkhodpay_flutter_bridge_sim_arm64.a" ] && [ -f "$LIBS_DIR/ios/libkhodpay_flutter_bridge_sim_x86_64.a" ]; then
    lipo -create \
        "$LIBS_DIR/ios/libkhodpay_flutter_bridge_sim_arm64.a" \
        "$LIBS_DIR/ios/libkhodpay_flutter_bridge_sim_x86_64.a" \
        -output "$LIBS_DIR/ios/libkhodpay_flutter_bridge_sim_universal.a"
    echo -e "${GREEN}   ✓ iOS Universal Simulator: libkhodpay_flutter_bridge_sim_universal.a (x86_64 + ARM64)${NC}"
fi

# Copy Android libraries
if [ -f "$BUILD_DIR/aarch64-linux-android/release/libkhodpay_flutter_bridge.so" ]; then
    cp "$BUILD_DIR/aarch64-linux-android/release/libkhodpay_flutter_bridge.so" "$LIBS_DIR/android/arm64-v8a/"
    echo -e "${GREEN}   ✓ Android ARM64: libkhodpay_flutter_bridge.so${NC}"
fi

if [ -f "$BUILD_DIR/armv7-linux-androideabi/release/libkhodpay_flutter_bridge.so" ]; then
    cp "$BUILD_DIR/armv7-linux-androideabi/release/libkhodpay_flutter_bridge.so" "$LIBS_DIR/android/armeabi-v7a/"
    echo -e "${GREEN}   ✓ Android ARMv7: libkhodpay_flutter_bridge.so${NC}"
fi

if [ -f "$BUILD_DIR/x86_64-linux-android/release/libkhodpay_flutter_bridge.so" ]; then
    cp "$BUILD_DIR/x86_64-linux-android/release/libkhodpay_flutter_bridge.so" "$LIBS_DIR/android/x86_64/"
    echo -e "${GREEN}   ✓ Android x86_64: libkhodpay_flutter_bridge.so${NC}"
fi

echo ""
echo -e "${YELLOW}🗑️  Cleaning up build artifacts...${NC}"

# Remove all build artifacts except the organized libs
rm -rf "$BUILD_DIR/release"
rm -rf "$BUILD_DIR/debug"
rm -rf "$BUILD_DIR/aarch64-apple-ios"
rm -rf "$BUILD_DIR/aarch64-apple-ios-sim"
rm -rf "$BUILD_DIR/x86_64-apple-ios"
rm -rf "$BUILD_DIR/aarch64-linux-android"
rm -rf "$BUILD_DIR/armv7-linux-androideabi"
rm -rf "$BUILD_DIR/i686-linux-android"
rm -rf "$BUILD_DIR/x86_64-linux-android"
rm -rf "$BUILD_DIR/.cargo-lock"
rm -f "$BUILD_DIR"/*.log

echo -e "${GREEN}   ✓ Removed intermediate build artifacts${NC}"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Libraries organized successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Show final structure
echo -e "${BLUE}📦 Final structure:${NC}"
du -sh "$LIBS_DIR"/* 2>/dev/null | while read size dir; do
    echo -e "   $size - $(basename $dir)"
done

echo ""
echo -e "${YELLOW}📁 Libraries ready for commit:${NC}"
echo -e "   build/libs/"
echo -e "   ├── macos/              (for Flutter macOS)"
echo -e "   ├── ios/                (for Flutter iOS)"
echo -e "   └── android/            (for Flutter Android)"
echo -e "       ├── arm64-v8a/"
echo -e "       ├── armeabi-v7a/"
echo -e "       └── x86_64/"
echo ""
echo -e "${GREEN}💡 Total size: $(du -sh $LIBS_DIR | cut -f1)${NC}"
echo ""
