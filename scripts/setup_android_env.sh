#!/bin/bash
# Setup Android NDK environment for building

# Find Android NDK
if [ -z "$ANDROID_NDK_HOME" ]; then
    if [ -d "$HOME/Library/Android/sdk/ndk" ]; then
        # Find the latest NDK version
        ANDROID_NDK_HOME=$(ls -d $HOME/Library/Android/sdk/ndk/* | sort -V | tail -1)
    fi
fi

if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "Error: ANDROID_NDK_HOME not set and could not auto-detect"
    exit 1
fi

export ANDROID_NDK_HOME

# Set up toolchain paths
TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64
export PATH=$TOOLCHAIN/bin:$PATH

# Set CC/AR for each Android target (for cc-rs crate)
export CC_aarch64_linux_android=$TOOLCHAIN/bin/aarch64-linux-android21-clang
export AR_aarch64_linux_android=$TOOLCHAIN/bin/llvm-ar
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$TOOLCHAIN/bin/aarch64-linux-android21-clang

export CC_armv7_linux_androideabi=$TOOLCHAIN/bin/armv7a-linux-androideabi21-clang  
export AR_armv7_linux_androideabi=$TOOLCHAIN/bin/llvm-ar
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=$TOOLCHAIN/bin/armv7a-linux-androideabi21-clang

export CC_i686_linux_android=$TOOLCHAIN/bin/i686-linux-android21-clang
export AR_i686_linux_android=$TOOLCHAIN/bin/llvm-ar
export CARGO_TARGET_I686_LINUX_ANDROID_LINKER=$TOOLCHAIN/bin/i686-linux-android21-clang

export CC_x86_64_linux_android=$TOOLCHAIN/bin/x86_64-linux-android21-clang
export AR_x86_64_linux_android=$TOOLCHAIN/bin/llvm-ar
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=$TOOLCHAIN/bin/x86_64-linux-android21-clang

echo "✓ Android NDK environment configured"
echo "  NDK: $ANDROID_NDK_HOME"
echo "  Toolchain: $TOOLCHAIN"
