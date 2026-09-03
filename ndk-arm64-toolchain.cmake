# Thin wrapper around the NDK's official CMake toolchain.
# Used by cmake-based -sys crates during Android cross-compilation
# (audiopus_sys builds libopus with this) to force the correct ABI —
# android-build.sh exports it via CMAKE_TOOLCHAIN_FILE_aarch64_linux_android.
# ANDROID_NDK_HOME is exported by android-build.sh.
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-26)  # keep in sync with minSdk
include("$ENV{ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake")
