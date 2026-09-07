#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🔧 KhodPay Wallet - Install Build Targets${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if rustup is installed
if ! command -v rustup &> /dev/null; then
    echo -e "${RED}❌ Error: rustup is not installed${NC}"
    echo -e "${YELLOW}Install it from: https://rustup.rs/${NC}"
    exit 1
fi

echo -e "${YELLOW}📦 Installing Rust targets for cross-compilation...${NC}"
echo ""

# iOS targets
echo -e "${BLUE}Installing iOS targets...${NC}"
rustup target add aarch64-apple-ios
rustup target add aarch64-apple-ios-sim
rustup target add x86_64-apple-ios

# Android targets
echo -e "${BLUE}Installing Android targets...${NC}"
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android

echo ""
echo -e "${GREEN}✅ All targets installed successfully!${NC}"
echo ""

# Check for Android NDK
echo -e "${YELLOW}🔍 Checking for Android NDK...${NC}"
if [ -z "$ANDROID_NDK_HOME" ] && [ -z "$NDK_HOME" ]; then
    echo -e "${YELLOW}⚠️  Warning: Android NDK environment variable not set${NC}"
    echo -e "${YELLOW}   To build for Android, you need to install Android NDK${NC}"
    echo -e "${YELLOW}   and set either ANDROID_NDK_HOME or NDK_HOME${NC}"
    echo ""
    echo -e "${BLUE}   Install Android NDK:${NC}"
    echo -e "   1. Install Android Studio"
    echo -e "   2. Open SDK Manager → SDK Tools → NDK (Side by side)"
    echo -e "   3. Set environment variable:"
    echo -e "      export ANDROID_NDK_HOME=\$HOME/Library/Android/sdk/ndk/<version>"
    echo ""
else
    if [ -n "$ANDROID_NDK_HOME" ]; then
        echo -e "${GREEN}✓ Android NDK found at: $ANDROID_NDK_HOME${NC}"
    else
        echo -e "${GREEN}✓ Android NDK found at: $NDK_HOME${NC}"
    fi
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}🎉 Setup complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}💡 Next step: Run ./scripts/build_rust.sh to build libraries${NC}"
echo ""
