#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  KhodPay Wallet - Complete Build Process                    ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Step 0: Populate GMP/MPFR/MPC cross-compile cache (skipped if already cached)
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}🔧 Step 0/4: Populating GMP cross-compile cache...${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
./scripts/build_gmp_cache.sh

# Step 1: Generate bridge code
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}📝 Step 1/4: Generating bridge code...${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
./scripts/generate_bridge.sh

# Step 2: Build Rust library
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}🔨 Step 2/4: Building Rust library...${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
./scripts/build_rust.sh release all

# Step 3: Create universal iOS library
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}🍎 Step 3/4: Creating universal iOS library...${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
./scripts/create_universal_ios.sh release

# Step 4: Organize libraries for git commit
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}📦 Step 4/4: Organizing libraries...${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
./scripts/organize_libs.sh

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅ Complete Build Process Finished Successfully!           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}📦 Deliverables (ready for git commit):${NC}"
echo -e "   ${GREEN}✓${NC} Dart bindings:    build/dart/"
echo -e "   ${GREEN}✓${NC} Native libraries: build/libs/ (organized by platform)"
echo -e "   ${GREEN}✓${NC} Universal iOS:    build/libs/ios/libkhodpay_flutter_bridge_sim_universal.a"
echo ""
echo -e "${YELLOW}📱 Flutter Integration:${NC}"
echo -e "   Copy from build/libs/ to your Flutter project:"
echo -e "   • macos/       → Flutter macOS app"
echo -e "   • ios/         → Flutter iOS frameworks (includes universal simulator)"
echo -e "   • android/     → Flutter android/app/src/main/jniLibs/"
echo ""
echo -e "${BLUE}🍎 iOS Universal Library:${NC}"
echo -e "   The universal simulator library supports both:"
echo -e "   • ${GREEN}✓${NC} Intel Macs (x86_64)"
echo -e "   • ${GREEN}✓${NC} Apple Silicon Macs (ARM64)"
echo ""
