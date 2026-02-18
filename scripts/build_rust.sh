#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

BUILD_MODE=${1:-release}  # Default to release build
PLATFORM=${2:-all}         # Default to all platforms

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🔨 KhodPay Wallet - Rust Library Builder${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}📋 Build Configuration:${NC}"
echo -e "   Mode:     ${BUILD_MODE}"
echo -e "   Platform: ${PLATFORM}"
echo ""

# Setup Android environment if needed
if [ "$PLATFORM" = "all" ] || [ "$PLATFORM" = "android" ]; then
    if [ -d "$HOME/Library/Android/sdk/ndk" ]; then
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [ -f "$SCRIPT_DIR/setup_android_env.sh" ]; then
            echo -e "${BLUE}Setting up Android NDK environment...${NC}"
            source "$SCRIPT_DIR/setup_android_env.sh"
        fi
    fi
fi

cd crates/flutter_bridge

# Array to track background build jobs
BUILD_PIDS=()
BUILD_NAMES=()

# Function to build for a specific target (supports parallel execution)
build_target() {
    local target=$1
    local name=$2
    local parallel=${3:-false}
    
    if [ "$parallel" = "true" ]; then
        # Launch build in background
        (
            if [ "$BUILD_MODE" = "debug" ]; then
                if [ -z "$target" ]; then
                    cargo build 2>&1
                else
                    cargo build --target "$target" 2>&1
                fi
            else
                if [ -z "$target" ]; then
                    cargo build --release 2>&1
                else
                    cargo build --release --target "$target" 2>&1
                fi
            fi
        ) > "../../build/build_${target:-native}_${BUILD_MODE}.log" 2>&1 &
        
        BUILD_PIDS+=($!)
        BUILD_NAMES+=("$name")
    else
        # Sequential build
        if [ "$BUILD_MODE" = "debug" ]; then
            echo -e "${BLUE}   Building: $name (debug)${NC}"
            if [ -z "$target" ]; then
                cargo build
            else
                cargo build --target "$target"
            fi
        else
            echo -e "${BLUE}   Building: $name (release)${NC}"
            if [ -z "$target" ]; then
                cargo build --release
            else
                cargo build --release --target "$target"
            fi
        fi
    fi
}

# Function to wait for all parallel builds to complete
wait_for_builds() {
    if [ ${#BUILD_PIDS[@]} -eq 0 ]; then
        return 0
    fi
    
    echo ""
    echo -e "${YELLOW}⏳ Waiting for ${#BUILD_PIDS[@]} parallel builds to complete...${NC}"
    
    local failed=0
    for i in "${!BUILD_PIDS[@]}"; do
        local pid=${BUILD_PIDS[$i]}
        local name=${BUILD_NAMES[$i]}
        
        if wait $pid; then
            echo -e "${GREEN}   ✓ ${name}${NC}"
        else
            echo -e "${RED}   ✗ ${name} (failed)${NC}"
            failed=1
        fi
    done
    
    # Reset arrays
    BUILD_PIDS=()
    BUILD_NAMES=()
    
    if [ $failed -eq 1 ]; then
        echo -e "${RED}Some builds failed. Check logs in build/ directory${NC}"
        return 1
    fi
    
    return 0
}

echo -e "${YELLOW}🔨 Building libraries...${NC}"
echo ""

if [ "$PLATFORM" = "all" ]; then
    # Build for all platforms IN PARALLEL
    echo -e "${GREEN}Building for all platforms (parallel)...${NC}"
    echo -e "${BLUE}Starting parallel compilation for maximum speed${NC}"
    
    # Launch all builds in parallel
    build_target "" "macOS/Desktop" true
    build_target "aarch64-apple-ios" "iOS ARM64" true
    build_target "aarch64-apple-ios-sim" "iOS Simulator ARM64" true
    build_target "x86_64-apple-ios" "iOS Simulator x86_64" true
    
    # Android (only if NDK is available)
    if [ -n "$ANDROID_NDK_HOME" ] || [ -n "$NDK_HOME" ] || [ -d "$HOME/Library/Android/sdk/ndk" ]; then
        build_target "aarch64-linux-android" "Android ARM64" true
        build_target "armv7-linux-androideabi" "Android ARMv7" true
        build_target "x86_64-linux-android" "Android x86_64" true
    else
        echo -e "${YELLOW}⚠️  Skipping Android: NDK not found${NC}"
        echo -e "${YELLOW}   Set ANDROID_NDK_HOME to enable Android builds${NC}"
    fi
    
    # Wait for all parallel builds to complete
    wait_for_builds || exit 1
    
elif [ "$PLATFORM" = "android" ]; then
    if [ -z "$ANDROID_NDK_HOME" ] && [ -z "$NDK_HOME" ] && [ ! -d "$HOME/Library/Android/sdk/ndk" ]; then
        echo -e "${RED}❌ Error: Android NDK not found${NC}"
        echo -e "${YELLOW}Set ANDROID_NDK_HOME or NDK_HOME environment variable${NC}"
        echo -e "${YELLOW}See ./scripts/setup_targets.sh for setup instructions${NC}"
        exit 1
    fi
    echo -e "${GREEN}Building Android targets (parallel)...${NC}"
    build_target "aarch64-linux-android" "Android ARM64" true
    build_target "armv7-linux-androideabi" "Android ARMv7" true
    build_target "x86_64-linux-android" "Android x86_64" true
    wait_for_builds || exit 1
    
elif [ "$PLATFORM" = "ios" ]; then
    echo -e "${GREEN}Building iOS targets (parallel)...${NC}"
    build_target "aarch64-apple-ios" "iOS ARM64" true
    build_target "aarch64-apple-ios-sim" "iOS Simulator ARM64" true
    build_target "x86_64-apple-ios" "iOS Simulator x86_64" true
    wait_for_builds || exit 1
    
elif [ "$PLATFORM" = "macos" ] || [ "$PLATFORM" = "desktop" ]; then
    build_target "" "macOS/Desktop"
    
else
    echo -e "${RED}Unknown platform: $PLATFORM${NC}"
    echo -e "${YELLOW}Valid options: all, android, ios, macos, desktop${NC}"
    exit 1
fi

cd ../..

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Build completed successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Show generated libraries
echo -e "${YELLOW}📦 Generated libraries:${NC}"
echo ""

# macOS/Desktop
if [ -f "build/rust/${BUILD_MODE}/libkhodpay_flutter_bridge.dylib" ]; then
    size=$(du -h "build/rust/${BUILD_MODE}/libkhodpay_flutter_bridge.dylib" | cut -f1)
    echo -e "${GREEN}✓ macOS/Desktop:${NC}"
    echo -e "  build/rust/${BUILD_MODE}/libkhodpay_flutter_bridge.dylib ($size)"
fi

if [ -f "build/rust/${BUILD_MODE}/libkhodpay_flutter_bridge.a" ]; then
    size=$(du -h "build/rust/${BUILD_MODE}/libkhodpay_flutter_bridge.a" | cut -f1)
    echo -e "  build/rust/${BUILD_MODE}/libkhodpay_flutter_bridge.a ($size)"
    echo ""
fi

# iOS
if [ -f "build/rust/aarch64-apple-ios/${BUILD_MODE}/libkhodpay_flutter_bridge.a" ]; then
    size=$(du -h "build/rust/aarch64-apple-ios/${BUILD_MODE}/libkhodpay_flutter_bridge.a" | cut -f1)
    echo -e "${GREEN}✓ iOS (Device):${NC}"
    echo -e "  build/rust/aarch64-apple-ios/${BUILD_MODE}/libkhodpay_flutter_bridge.a ($size)"
    echo ""
fi

if [ -f "build/rust/aarch64-apple-ios-sim/${BUILD_MODE}/libkhodpay_flutter_bridge.a" ]; then
    size=$(du -h "build/rust/aarch64-apple-ios-sim/${BUILD_MODE}/libkhodpay_flutter_bridge.a" | cut -f1)
    echo -e "${GREEN}✓ iOS (Simulator ARM64):${NC}"
    echo -e "  build/rust/aarch64-apple-ios-sim/${BUILD_MODE}/libkhodpay_flutter_bridge.a ($size)"
    echo ""
fi

if [ -f "build/rust/x86_64-apple-ios/${BUILD_MODE}/libkhodpay_flutter_bridge.a" ]; then
    size=$(du -h "build/rust/x86_64-apple-ios/${BUILD_MODE}/libkhodpay_flutter_bridge.a" | cut -f1)
    echo -e "${GREEN}✓ iOS (Simulator x86_64):${NC}"
    echo -e "  build/rust/x86_64-apple-ios/${BUILD_MODE}/libkhodpay_flutter_bridge.a ($size)"
    echo ""
fi

# Android
if [ -f "build/rust/aarch64-linux-android/${BUILD_MODE}/libkhodpay_flutter_bridge.so" ]; then
    size=$(du -h "build/rust/aarch64-linux-android/${BUILD_MODE}/libkhodpay_flutter_bridge.so" | cut -f1)
    echo -e "${GREEN}✓ Android (ARM64):${NC}"
    echo -e "  build/rust/aarch64-linux-android/${BUILD_MODE}/libkhodpay_flutter_bridge.so ($size)"
fi

if [ -f "build/rust/armv7-linux-androideabi/${BUILD_MODE}/libkhodpay_flutter_bridge.so" ]; then
    size=$(du -h "build/rust/armv7-linux-androideabi/${BUILD_MODE}/libkhodpay_flutter_bridge.so" | cut -f1)
    echo -e "  build/rust/armv7-linux-androideabi/${BUILD_MODE}/libkhodpay_flutter_bridge.so ($size)"
fi

if [ -f "build/rust/x86_64-linux-android/${BUILD_MODE}/libkhodpay_flutter_bridge.so" ]; then
    size=$(du -h "build/rust/x86_64-linux-android/${BUILD_MODE}/libkhodpay_flutter_bridge.so" | cut -f1)
    echo -e "  build/rust/x86_64-linux-android/${BUILD_MODE}/libkhodpay_flutter_bridge.so ($size)"
fi

echo ""
echo -e "${YELLOW}💡 Libraries ready for Flutter integration!${NC}"
echo ""
echo -e "${BLUE}Usage:${NC}"
echo -e "  ./scripts/build_rust.sh [mode] [platform]"
echo -e "  mode:     release (default) | debug"
echo -e "  platform: all (default) | android | ios | macos | desktop"
echo ""
