#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🔨 KhodPay Wallet - Flutter Rust Bridge Code Generator${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if flutter_rust_bridge_codegen is installed
if ! command -v flutter_rust_bridge_codegen &> /dev/null; then
    echo -e "${RED}❌ Error: flutter_rust_bridge_codegen is not installed${NC}"
    echo -e "${YELLOW}📦 Install it with: cargo install flutter_rust_bridge_codegen${NC}"
    exit 1
fi

echo -e "${YELLOW}📋 Checking prerequisites...${NC}"
echo -e "   ✓ flutter_rust_bridge_codegen found"

# Create build/dart directory if it doesn't exist
echo ""
echo -e "${YELLOW}📁 Creating build directories...${NC}"
mkdir -p build/dart
echo -e "   ✓ build/dart created"

# Run the code generator
echo ""
echo -e "${YELLOW}🚀 Generating bridge code...${NC}"
echo -e "${BLUE}   Input:  crate::bridge (from crates/flutter_bridge)${NC}"
echo -e "${BLUE}   Output: build/dart/${NC}"
echo -e "${BLUE}   Output: crates/flutter_bridge/src/bridge_generated.rs${NC}"
echo ""

flutter_rust_bridge_codegen generate \
  --rust-input "crate::bridge" \
  --rust-root "crates/flutter_bridge" \
  --dart-output "build/dart/" \
  --rust-output "crates/flutter_bridge/src/bridge_generated.rs" \
  --dart-entrypoint-class-name "RustLib" \
  --no-add-mod-to-lib

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Bridge code generation completed successfully!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}📦 Generated files:${NC}"
echo -e "   ${GREEN}✓${NC} Dart bindings:  build/dart/bridge_generated.dart"
echo -e "   ${GREEN}✓${NC} Rust bindings:  crates/flutter_bridge/src/bridge_generated.rs"
echo ""
echo -e "${YELLOW}💡 Next step: Run ./scripts/build_rust.sh to build the library${NC}"
echo ""
