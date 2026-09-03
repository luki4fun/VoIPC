#!/usr/bin/env bash
# One-time Android build environment setup for VoIPC.
# Installs a self-contained Android SDK to ~/android-sdk (a location
# android-build.sh auto-detects): commandline-tools, platform, build-tools,
# NDK, a JDK 21 (the Android Gradle plugin needs 17-21; the system Java may
# be too new), and the Rust cross-compile targets.
#
# Re-runnable: each step is skipped if already present.
#
# Versions: the platform and build-tools follow compileSdk in
# client/src-tauri/gen/android/app/build.gradle.kts automatically (tauri
# maintains that file) — when compileSdk moves, re-running this script
# installs the matching packages. The remaining pins can be overridden via
# environment variables (ANDROID_HOME, NDK_VERSION, CMDTOOLS_URL, JDK_URL);
# the NDK pin should only move together with a tested build.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

SDK="${ANDROID_HOME:-$HOME/android-sdk}"
CMDTOOLS_URL="${CMDTOOLS_URL:-https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip}"
# latest GA JDK 21 — major version pinned because the Android Gradle plugin supports 17-21
JDK_URL="${JDK_URL:-https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse}"
NDK_VERSION="${NDK_VERSION:-28.0.13004108}"

# Follow compileSdk from the gradle file tauri generates (fallback: 36)
COMPILE_SDK="$(grep -oP 'compileSdk\s*=\s*\K[0-9]+' \
    "$SCRIPT_DIR/client/src-tauri/gen/android/app/build.gradle.kts" 2>/dev/null || echo 36)"
PLATFORM="android-$COMPILE_SDK"
BUILD_TOOLS="$COMPILE_SDK.0.0"

info() { echo -e "\033[1;33m[..]\033[0m $*"; }
ok()   { echo -e "\033[0;32m[ok]\033[0m $*"; }

mkdir -p "$SDK"

# ── commandline-tools ─────────────────────────────────────────────────────
if [[ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]]; then
    info "Downloading Android commandline-tools..."
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/cmdtools.zip" "$CMDTOOLS_URL"
    unzip -q "$tmp/cmdtools.zip" -d "$tmp"
    # the zip contains cmdline-tools/ — sdkmanager expects cmdline-tools/latest/
    mkdir -p "$SDK/cmdline-tools"
    mv "$tmp/cmdline-tools" "$SDK/cmdline-tools/latest"
    rm -rf "$tmp"
fi
ok "commandline-tools"

# ── JDK 21 (bundled inside the SDK so no system Java is required) ─────────
if [[ ! -x "$SDK/jdk/bin/java" ]]; then
    info "Downloading Temurin JDK 21..."
    curl -fsSL -o "$SDK/jdk21.tar.gz" "$JDK_URL"
    mkdir -p "$SDK/jdk"
    tar -xzf "$SDK/jdk21.tar.gz" -C "$SDK/jdk" --strip-components=1
    rm -f "$SDK/jdk21.tar.gz"
fi
export JAVA_HOME="$SDK/jdk"
ok "JDK 21 ($("$JAVA_HOME/bin/java" -version 2>&1 | head -1))"

# ── SDK packages ──────────────────────────────────────────────────────────
SDKMANAGER="$SDK/cmdline-tools/latest/bin/sdkmanager"
info "Accepting licenses..."
# (yes || true): sdkmanager exits early when all licenses are already
# accepted, killing `yes` with SIGPIPE — don't let pipefail abort on that
(yes || true) | "$SDKMANAGER" --sdk_root="$SDK" --licenses > /dev/null
info "Installing platform-tools, $PLATFORM, build-tools;$BUILD_TOOLS, ndk;$NDK_VERSION (large download)..."
"$SDKMANAGER" --sdk_root="$SDK" \
    "platform-tools" "platforms;$PLATFORM" "build-tools;$BUILD_TOOLS" "ndk;$NDK_VERSION"
ok "SDK packages"

# ── Rust cross-compile targets ────────────────────────────────────────────
info "Adding Rust Android targets..."
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
ok "Rust targets"

echo ""
ok "Android environment ready at $SDK"
echo "Build with: ./android-build.sh [debug|release] [--target aarch64|armv7|x86_64|all]"
