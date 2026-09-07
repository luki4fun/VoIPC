# CMake toolchain wrapper for the Linux -> Windows cross build (build-windows.sh).
#
# cargo-xwin generates its own toolchain file (clang-cl + lld-link + the xwin
# CRT/SDK include paths) and points the `cmake` crate at it through
# CMAKE_TOOLCHAIN_FILE_x86_64_pc_windows_msvc. The crate checks the dashed
# spelling first, so build-windows.sh sets
# CMAKE_TOOLCHAIN_FILE_x86_64-pc-windows-msvc to this file, which includes
# cargo-xwin's and then applies the fixes below.

if(NOT DEFINED ENV{XWIN_CACHE_DIR})
    message(FATAL_ERROR "XWIN_CACHE_DIR is not set - run this build through ./build-windows.sh")
endif()

set(_xwin_toolchain
    "$ENV{XWIN_CACHE_DIR}/cmake/clang-cl/x86_64-pc-windows-msvc-toolchain.cmake")
if(NOT EXISTS "${_xwin_toolchain}")
    message(FATAL_ERROR "cargo-xwin toolchain file not found at ${_xwin_toolchain}")
endif()
include("${_xwin_toolchain}")

# Opus (audiopus_sys) applies the per-file -msse4.1 / -mavx that its SIMD
# sources need only `if(NOT MSVC)`, because real MSVC accepts those intrinsics
# without a target-feature flag. clang-cl makes CMake set MSVC, but is strict
# like GCC/Clang, so those files fail with "always_inline function
# '_mm_cvtepi8_epi32' requires target feature 'sse4.1'".
#
# Turning the flag on globally would let the compiler emit SSE4.1/AVX in the
# baseline code too, silently raising the CPU requirement of the whole app, so
# instead drop just these dispatch paths. Opus still detects CPU features at
# runtime and uses its C/SSE2 paths, which costs a fraction of a percent of one
# core for 48 kHz voice. The native Windows build (MSVC) keeps them.
set(OPUS_X86_MAY_HAVE_SSE4_1 OFF CACHE BOOL "disabled under clang-cl" FORCE)
set(OPUS_X86_MAY_HAVE_AVX OFF CACHE BOOL "disabled under clang-cl" FORCE)
