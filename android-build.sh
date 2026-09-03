#!/usr/bin/env bash
# Build VoIPC Android APK
# Usage: ./android-build.sh [debug|release] [--target aarch64|armv7|x86_64|all]
#
# Release signing uses keystore.properties at the repo root.
# Copy keystore.properties.example to keystore.properties and fill in your values.
#
# SDK/NDK/JDK locations are taken from ANDROID_HOME / ANDROID_NDK_HOME /
# JAVA_HOME when set, otherwise auto-detected from common install paths.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

export PATH="$HOME/.cargo/bin:$PATH"

# ── Android SDK ───────────────────────────────────────────────────────────
if [[ -z "${ANDROID_HOME:-}" ]]; then
    for d in "$HOME/Android/Sdk" "$HOME/android-sdk" /opt/android-sdk "$HOME/Library/Android/sdk"; do
        if [[ -d "$d" ]]; then export ANDROID_HOME="$d"; break; fi
    done
fi
if [[ -z "${ANDROID_HOME:-}" || ! -d "$ANDROID_HOME" ]]; then
    echo "ERROR: Android SDK not found." >&2
    echo "Install it via Android Studio or sdkmanager, then set ANDROID_HOME (e.g. ~/Android/Sdk)." >&2
    exit 1
fi

# ── Android NDK (newest installed one unless ANDROID_NDK_HOME is set) ─────
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
fi
if [[ -z "${ANDROID_NDK_HOME:-}" || ! -d "$ANDROID_NDK_HOME" ]]; then
    echo "ERROR: Android NDK not found under $ANDROID_HOME/ndk." >&2
    echo "Install one (e.g. 'sdkmanager \"ndk;28.0.13004108\"') or set ANDROID_NDK_HOME." >&2
    exit 1
fi
export ANDROID_NDK_HOME
export NDK_HOME="$ANDROID_NDK_HOME"

# ── JDK (android-setup.sh bundles one inside the SDK; probe that first) ──
if [[ -z "${JAVA_HOME:-}" ]]; then
    for d in "$ANDROID_HOME/jdk" \
             /usr/lib/jvm/java-21-openjdk-amd64 /usr/lib/jvm/java-21-openjdk \
             /usr/lib/jvm/java-17-openjdk-amd64 /usr/lib/jvm/java-17-openjdk \
             /usr/lib/jvm/default; do
        if [[ -d "$d" ]]; then export JAVA_HOME="$d"; break; fi
    done
fi
if [[ -z "${JAVA_HOME:-}" ]] && command -v javac >/dev/null; then
    export JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
fi
if [[ -z "${JAVA_HOME:-}" ]]; then
    echo "ERROR: No JDK found — install OpenJDK 21 (the Android Gradle plugin needs 17–21) or set JAVA_HOME." >&2
    exit 1
fi

NDK_TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
if [[ ! -d "$NDK_TOOLCHAIN" ]]; then
    echo "ERROR: NDK toolchain missing at $NDK_TOOLCHAIN" >&2
    exit 1
fi

echo "ANDROID_HOME:     $ANDROID_HOME"
echo "ANDROID_NDK_HOME: $ANDROID_NDK_HOME"
echo "JAVA_HOME:        $JAVA_HOME"

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

# CMake 4 removed compatibility with project files declaring < 3.5 (libopus
# does) — tell CMake to treat them as 3.5 instead of hard-erroring.
export CMAKE_POLICY_VERSION_MINIMUM=3.5

# Bundle libc++_shared.so — required because oboe-sys (C++) introduces
# __cxa_pure_virtual etc. that need the C++ runtime at load time.
NDK_SYSROOT="$NDK_TOOLCHAIN/sysroot/usr/lib"
JNILIBS="$SCRIPT_DIR/client/src-tauri/gen/android/app/src/main/jniLibs"
mkdir -p "$JNILIBS/arm64-v8a"
cp -u "$NDK_SYSROOT/aarch64-linux-android/libc++_shared.so" "$JNILIBS/arm64-v8a/" 2>/dev/null || true

# ── Parse args ────────────────────────────────────────────────────────────
BUILD_TYPE="debug"
TARGET="aarch64"
while [[ $# -gt 0 ]]; do
    case "$1" in
        debug|release) BUILD_TYPE="$1" ;;
        --target) TARGET="${2:?--target needs a value}"; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
    shift
done

check_signing() {
    if [[ ! -f "$SCRIPT_DIR/keystore.properties" ]]; then
        echo "ERROR: keystore.properties not found at repo root."
        echo "Copy keystore.properties.example to keystore.properties and fill in your keystore details."
        exit 1
    fi
}

# The tauri CLI comes from the client's npm devDependencies — no global install needed
cd "$SCRIPT_DIR/client"
[ -d node_modules ] || npm install

if [[ "$BUILD_TYPE" == "release" ]]; then
    check_signing
    echo "Building VoIPC Android (release)..."
    npx tauri android build --target "$TARGET"
else
    echo "Building VoIPC Android (debug)..."
    npx tauri android build --target "$TARGET" --debug
fi
cd "$SCRIPT_DIR"

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
