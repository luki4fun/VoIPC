#!/bin/bash
# Build VoIPC Android APK
# Usage: ./android-build.sh [debug|release] [--target aarch64|armv7|x86_64|all]
#
# Release signing uses keystore.properties at the repo root.
# Copy keystore.properties.example to keystore.properties and fill in your values.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Environment setup
export PATH="$HOME/.cargo/bin:$PATH"
export ANDROID_HOME="/home/lukas/unfug/twhoshot/android/mic-bridge/android-sdk"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.0.13004108"
export NDK_HOME="$ANDROID_NDK_HOME"
export JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"

NDK_TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"

# Cross-compilation env vars for CC/CXX/AR
export CC_aarch64_linux_android="$NDK_TOOLCHAIN/bin/aarch64-linux-android26-clang"
export CXX_aarch64_linux_android="$NDK_TOOLCHAIN/bin/aarch64-linux-android26-clang++"
export AR_aarch64_linux_android="$NDK_TOOLCHAIN/bin/llvm-ar"
export RANLIB_aarch64_linux_android="$NDK_TOOLCHAIN/bin/llvm-ranlib"

export CC_armv7_linux_androideabi="$NDK_TOOLCHAIN/bin/armv7a-linux-androideabi26-clang"
export CXX_armv7_linux_androideabi="$NDK_TOOLCHAIN/bin/armv7a-linux-androideabi26-clang++"
export AR_armv7_linux_androideabi="$NDK_TOOLCHAIN/bin/llvm-ar"
export RANLIB_armv7_linux_androideabi="$NDK_TOOLCHAIN/bin/llvm-ranlib"

export CC_x86_64_linux_android="$NDK_TOOLCHAIN/bin/x86_64-linux-android26-clang"
export CXX_x86_64_linux_android="$NDK_TOOLCHAIN/bin/x86_64-linux-android26-clang++"
export AR_x86_64_linux_android="$NDK_TOOLCHAIN/bin/llvm-ar"
export RANLIB_x86_64_linux_android="$NDK_TOOLCHAIN/bin/llvm-ranlib"

# CMake toolchain wrapper (forces correct ABI for Opus cross-compilation)
export CMAKE_TOOLCHAIN_FILE_aarch64_linux_android="$SCRIPT_DIR/ndk-arm64-toolchain.cmake"

# Bundle libc++_shared.so — required because oboe-sys (C++) introduces
# __cxa_pure_virtual etc. that need the C++ runtime at load time.
NDK_SYSROOT="$NDK_TOOLCHAIN/sysroot/usr/lib"
JNILIBS="$SCRIPT_DIR/client/src-tauri/gen/android/app/src/main/jniLibs"
mkdir -p "$JNILIBS/arm64-v8a"
cp -u "$NDK_SYSROOT/aarch64-linux-android/libc++_shared.so" "$JNILIBS/arm64-v8a/" 2>/dev/null || true

# Parse args
BUILD_TYPE="${1:-debug}"
TARGET="${3:-aarch64}"

check_signing() {
    if [[ ! -f "$SCRIPT_DIR/keystore.properties" ]]; then
        echo "ERROR: keystore.properties not found at repo root."
        echo "Copy keystore.properties.example to keystore.properties and fill in your keystore details."
        exit 1
    fi
}

if [[ "$BUILD_TYPE" == "release" ]]; then
    check_signing
    echo "Building VoIPC Android (release)..."
    cargo tauri android build --target "$TARGET"
else
    echo "Building VoIPC Android (debug)..."
    cargo tauri android build --target "$TARGET" --debug
fi

echo ""
echo "Build complete!"

# Copy APK to release/ for easy access
mkdir -p "$SCRIPT_DIR/release"
if [[ "$BUILD_TYPE" == "release" ]]; then
    APK_DIR="client/src-tauri/gen/android/app/build/outputs/apk/universal/release"
    APK=$(find "$APK_DIR" -name "*.apk" | head -1)
    if [[ -n "$APK" ]]; then
        cp "$APK" "$SCRIPT_DIR/release/VoIPC-android-release.apk"
        echo "APK: release/VoIPC-android-release.apk"
    fi
else
    APK="client/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
    if [[ -f "$APK" ]]; then
        cp "$APK" "$SCRIPT_DIR/release/VoIPC-android-debug.apk"
        echo "APK: release/VoIPC-android-debug.apk"
    fi
fi
