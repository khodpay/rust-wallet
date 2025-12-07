#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

BUILD_MODE=${1:-release}

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🔨 Creating Universal iOS Libraries${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}📋 Build Mode: ${BUILD_MODE}${NC}"
echo ""

# Check if lipo is available
if ! command -v lipo &> /dev/null; then
    echo -e "${RED}❌ Error: lipo command not found${NC}"
    echo -e "${YELLOW}lipo is required to create universal binaries${NC}"
    exit 1
fi

# Paths
ARM64_SIM="build/rust/aarch64-apple-ios-sim/${BUILD_MODE}/libkhodpay_flutter_bridge.a"
X86_64_SIM="build/rust/x86_64-apple-ios/${BUILD_MODE}/libkhodpay_flutter_bridge.a"
DEVICE="build/rust/aarch64-apple-ios/${BUILD_MODE}/libkhodpay_flutter_bridge.a"
OUTPUT_DIR="build/libs/ios"
UNIVERSAL_SIM="${OUTPUT_DIR}/libkhodpay_flutter_bridge_sim_universal.a"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if simulator libraries exist
if [ ! -f "$ARM64_SIM" ]; then
    echo -e "${RED}❌ Error: ARM64 simulator library not found${NC}"
    echo -e "${YELLOW}Expected: $ARM64_SIM${NC}"
    echo -e "${YELLOW}Run: ./scripts/build_rust.sh ${BUILD_MODE} ios${NC}"
    exit 1
fi

if [ ! -f "$X86_64_SIM" ]; then
    echo -e "${RED}❌ Error: x86_64 simulator library not found${NC}"
    echo -e "${YELLOW}Expected: $X86_64_SIM${NC}"
    echo -e "${YELLOW}Run: ./scripts/build_rust.sh ${BUILD_MODE} ios${NC}"
    exit 1
fi

# Create universal simulator library (ARM64 + x86_64)
echo -e "${BLUE}Creating universal simulator library...${NC}"
echo -e "  Combining: ARM64 + x86_64"
lipo -create "$ARM64_SIM" "$X86_64_SIM" -output "$UNIVERSAL_SIM"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Universal simulator library created${NC}"
    size=$(du -h "$UNIVERSAL_SIM" | cut -f1)
    echo -e "  ${UNIVERSAL_SIM} ($size)"
    
    # Show architectures
    echo ""
    echo -e "${YELLOW}Architectures in universal library:${NC}"
    lipo -info "$UNIVERSAL_SIM"
else
    echo -e "${RED}❌ Failed to create universal library${NC}"
    exit 1
fi

# Copy device library
if [ -f "$DEVICE" ]; then
    echo ""
    echo -e "${BLUE}Copying device library...${NC}"
    cp "$DEVICE" "${OUTPUT_DIR}/libkhodpay_flutter_bridge_device.a"
    echo -e "${GREEN}✓ Device library copied${NC}"
    size=$(du -h "${OUTPUT_DIR}/libkhodpay_flutter_bridge_device.a" | cut -f1)
    echo -e "  ${OUTPUT_DIR}/libkhodpay_flutter_bridge_device.a ($size)"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Universal iOS libraries created successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}📦 Output files:${NC}"
echo -e "  ${UNIVERSAL_SIM}"
echo -e "  ${OUTPUT_DIR}/libkhodpay_flutter_bridge_device.a"
echo ""
echo -e "${YELLOW}💡 Usage in Flutter:${NC}"
echo -e "  Copy these libraries to your Flutter project's ios/Frameworks/ directory"
echo -e "  The universal simulator library works on both Intel and Apple Silicon Macs"
echo ""
