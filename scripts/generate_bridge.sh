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

# Create/update minimal pubspec.yaml for code generation
echo -e "${YELLOW}📝 Creating/updating pubspec.yaml for code generation...${NC}"
cat > build/dart/pubspec.yaml << 'EOF'
name: khodpay_bridge
description: KhodPay Wallet Rust Bridge
version: 1.0.0
publish_to: none

environment:
  sdk: '>=3.0.0 <4.0.0'

dependencies:
  flutter:
    sdk: flutter
  flutter_rust_bridge: ^2.11.1
  ffi: ^2.1.0
  meta: ^1.10.0
  freezed_annotation: ^2.4.1

dev_dependencies:
  freezed: ^2.4.5
  build_runner: ^2.4.6
EOF
echo -e "   ✓ pubspec.yaml updated with required dependencies"

# Run the code generator
echo ""
echo -e "${YELLOW}🚀 Generating bridge code...${NC}"
echo -e "${BLUE}   Input:  crate::bridge (from crates/flutter_bridge)${NC}"
echo -e "${BLUE}   Output: build/dart/${NC}"
echo -e "${BLUE}   Output: crates/flutter_bridge/src/bridge_generated.rs${NC}"
echo ""

# Get absolute paths
PROJECT_ROOT=$(pwd)
RUST_ROOT="$PROJECT_ROOT/crates/flutter_bridge"
DART_OUTPUT="$PROJECT_ROOT/build/dart"
RUST_OUTPUT="$PROJECT_ROOT/crates/flutter_bridge/src/bridge_generated.rs"

# Change to dart output directory so flutter_rust_bridge_codegen can find pubspec.yaml
cd "$DART_OUTPUT"

# Run code generator with absolute paths
flutter_rust_bridge_codegen generate \
  --rust-input "crate::bridge" \
  --rust-root "$RUST_ROOT" \
  --dart-output "$DART_OUTPUT" \
  --rust-output "$RUST_OUTPUT" \
  --dart-entrypoint-class-name "RustLib" \
  --no-add-mod-to-lib

# Return to original directory
cd "$PROJECT_ROOT"

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
