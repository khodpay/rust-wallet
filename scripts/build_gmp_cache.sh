#!/bin/bash
# build_gmp_cache.sh
#
# Builds GMP, MPFR, and MPC from the bundled sources inside gmp-mpfr-sys and
# populates the gmp-mpfr-sys cache directory so that cross-compilation targets
# (iOS, Android) skip the C-build step entirely during `cargo build`.
#
# Cache layout expected by gmp-mpfr-sys 1.7.x:
#   ~/Library/Caches/gmp-mpfr-sys/1.7/<target>/1.7.1/
#       libgmp.a  libmpfr.a  libmpc.a  gmp.h  mpfr.h  mpc.h
#
# Run once before `./scripts/build_all.sh`.
# Safe to re-run: existing cache entries are skipped.

set -e

# ── Paths ─────────────────────────────────────────────────────────────────────

GMP_MPFR_SYS_SRC="$HOME/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/gmp-mpfr-sys-1.7.1"
GMP_SRC="$GMP_MPFR_SYS_SRC/gmp-6.3.0-c"
MPFR_SRC="$GMP_MPFR_SYS_SRC/mpfr-4.2.2-c"
MPC_SRC="$GMP_MPFR_SYS_SRC/mpc-1.4.1-c"
CACHE_BASE="$HOME/Library/Caches/gmp-mpfr-sys/1.7"
CACHE_VERSION="1.7.1"
TMPDIR_BASE="/tmp/gmp-mpfr-cross-build"

NDK_HOME="$HOME/Library/Android/sdk/ndk/29.0.14033849"
TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64"
IOS_SDK=$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
SIM_SDK=$(xcrun --sdk iphonesimulator --show-sdk-path 2>/dev/null)
CLANG=$(xcrun -find clang)
AR_TOOL=$(xcrun -find ar)

# ── Colors ────────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'

# ── Helper: build GMP + MPFR + MPC for one target ────────────────────────────
#
# Arguments:
#   $1  Rust/Cargo target triple          e.g. aarch64-apple-ios
#   $2  GMP --host value                  e.g. aarch64-apple-ios
#   $3  CC (cross-compiler binary)
#   $4  CFLAGS (target/sysroot flags)
#   $5  AR binary
#   $6  RANLIB binary (pass "ranlib" for default)

build_for_target() {
    local rust_target="$1"
    local gmp_host="$2"
    local cc="$3"
    local cflags="$4"
    local ar="$5"
    local ranlib="$6"

    local cache_dir="$CACHE_BASE/$rust_target/$CACHE_VERSION"

    # Skip if already cached.
    if [ -f "$cache_dir/libgmp.a" ] && [ -f "$cache_dir/libmpfr.a" ] && [ -f "$cache_dir/libmpc.a" ]; then
        echo -e "  ${GREEN}✓ $rust_target (already cached)${NC}"
        return 0
    fi

    echo -e "  ${YELLOW}⏳ Building $rust_target …${NC}"
    local work="$TMPDIR_BASE/$rust_target"
    rm -rf "$work"
    mkdir -p "$work"

    # Common configure flags.
    # --disable-assembly: use portable C instead of hand-written ASM.
    # GMP's ARM64 asm uses non-PIC ADR/ADRP patterns that iOS/Android
    # linkers reject. Pure C is slower but compiles cleanly everywhere.
    local cfg_common="--disable-shared --with-pic --disable-dependency-tracking --disable-assembly"

    # ── GMP ──────────────────────────────────────────────────────────────────
    mkdir -p "$work/gmp-build"
    (
        cd "$work/gmp-build"
        CC="$cc" CFLAGS="$cflags" AR="$ar" RANLIB="$ranlib" \
        "$GMP_SRC/configure" $cfg_common \
            --host="$gmp_host" \
            --prefix="$work/install" \
            2>&1
        make -j"$(sysctl -n hw.logicalcpu)" 2>&1
        make install 2>&1
    ) > "$work/gmp-build.log" 2>&1 || {
        echo -e "  ${RED}✗ GMP build failed for $rust_target — see $work/gmp-build.log${NC}"
        tail -20 "$work/gmp-build.log" >&2
        return 1
    }

    # ── MPFR ─────────────────────────────────────────────────────────────────
    mkdir -p "$work/mpfr-build"
    (
        cd "$work/mpfr-build"
        CC="$cc" CFLAGS="$cflags" AR="$ar" RANLIB="$ranlib" \
        "$MPFR_SRC/configure" $cfg_common \
            --host="$gmp_host" \
            --prefix="$work/install" \
            --with-gmp="$work/install" \
            2>&1
        make -j"$(sysctl -n hw.logicalcpu)" 2>&1
        make install 2>&1
    ) > "$work/mpfr-build.log" 2>&1 || {
        echo -e "  ${RED}✗ MPFR build failed for $rust_target — see $work/mpfr-build.log${NC}"
        return 1
    }

    # ── MPC ──────────────────────────────────────────────────────────────────
    mkdir -p "$work/mpc-build"
    (
        cd "$work/mpc-build"
        # API 23+ exposes creal/cimag in complex.h. Since we build the cache
        # with android23-clang, no extra flags are needed here.
        CC="$cc" CFLAGS="$cflags" AR="$ar" RANLIB="$ranlib" \
        "$MPC_SRC/configure" $cfg_common \
            --host="$gmp_host" \
            --prefix="$work/install" \
            --with-gmp="$work/install" \
            --with-mpfr="$work/install" \
            2>&1
        make -j"$(sysctl -n hw.logicalcpu)" 2>&1
        make install 2>&1
    ) > "$work/mpc-build.log" 2>&1 || {
        echo -e "  ${RED}✗ MPC build failed for $rust_target — see $work/mpc-build.log${NC}"
        return 1
    }

    # ── Populate cache ────────────────────────────────────────────────────────
    mkdir -p "$cache_dir"
    cp "$work/install/lib/libgmp.a"  "$cache_dir/"
    cp "$work/install/lib/libmpfr.a" "$cache_dir/"
    cp "$work/install/lib/libmpc.a"  "$cache_dir/"
    cp "$work/install/include/gmp.h"  "$cache_dir/"
    cp "$work/install/include/mpfr.h" "$cache_dir/"
    cp "$work/install/include/mpc.h"  "$cache_dir/"

    echo -e "  ${GREEN}✓ $rust_target — cached in $cache_dir${NC}"
}

# ── Main ──────────────────────────────────────────────────────────────────────

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}🔧 KhodPay — GMP/MPFR/MPC cross-compile cache builder${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [ ! -d "$GMP_SRC" ]; then
    echo -e "${RED}❌ gmp-mpfr-sys source not found at:${NC}"
    echo "   $GMP_MPFR_SYS_SRC"
    echo "   Run 'cargo fetch' first."
    exit 1
fi

mkdir -p "$TMPDIR_BASE"

echo -e "${YELLOW}Building iOS targets…${NC}"

# iOS Device (aarch64)
build_for_target \
    "aarch64-apple-ios" \
    "aarch64-apple-ios" \
    "$CLANG" \
    "-arch arm64 -target aarch64-apple-ios -isysroot $IOS_SDK -miphoneos-version-min=14.0" \
    "$AR_TOOL" \
    "ranlib"

# iOS Simulator ARM64 (Apple Silicon Mac)
build_for_target \
    "aarch64-apple-ios-sim" \
    "aarch64-apple-ios" \
    "$CLANG" \
    "-arch arm64 -target arm64-apple-ios-simulator -isysroot $SIM_SDK -miphoneos-version-min=14.0" \
    "$AR_TOOL" \
    "ranlib"

# iOS Simulator x86_64 (Intel Mac)
build_for_target \
    "x86_64-apple-ios" \
    "x86_64-apple-ios" \
    "$CLANG" \
    "-arch x86_64 -target x86_64-apple-ios-simulator -isysroot $SIM_SDK -miphoneos-version-min=14.0" \
    "$AR_TOOL" \
    "ranlib"

echo ""
echo -e "${YELLOW}Building Android targets…${NC}"

# Android ARM64
build_for_target \
    "aarch64-linux-android" \
    "aarch64-linux-android" \
    "$TOOLCHAIN/bin/aarch64-linux-android23-clang" \
    "" \
    "$TOOLCHAIN/bin/llvm-ar" \
    "$TOOLCHAIN/bin/llvm-ranlib"

# Android ARMv7
build_for_target \
    "armv7-linux-androideabi" \
    "armv7a-linux-androideabi" \
    "$TOOLCHAIN/bin/armv7a-linux-androideabi23-clang" \
    "" \
    "$TOOLCHAIN/bin/llvm-ar" \
    "$TOOLCHAIN/bin/llvm-ranlib"

# Android x86_64
build_for_target \
    "x86_64-linux-android" \
    "x86_64-linux-android" \
    "$TOOLCHAIN/bin/x86_64-linux-android23-clang" \
    "" \
    "$TOOLCHAIN/bin/llvm-ar" \
    "$TOOLCHAIN/bin/llvm-ranlib"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ GMP cache populated. Run ./scripts/build_all.sh now.${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
# Clean up temp build dirs (only on full success)
rm -rf "$TMPDIR_BASE"
