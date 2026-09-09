# CMake toolchain wrapper for the Linux -> Windows cross build.
#
# cargo-xwin generates its own toolchain file (clang-cl + lld-link + the xwin
# CRT/SDK include paths) and points the `cmake` crate at it through the
# environment variable CMAKE_TOOLCHAIN_FILE_x86_64_pc_windows_msvc. The crate
# looks up the *dashed* spelling of that name first, and .cargo/config.toml
# sets that one to this file — so this runs instead, chains to cargo-xwin's,
# and then applies the fix below.
#
# Reading cargo-xwin's path out of its own variable rather than rebuilding it
# from XWIN_CACHE_DIR means this file is correct wherever cargo-xwin puts it,
# and that it can tell whether a cargo-xwin build is happening at all: on a
# native Windows build nothing sets that variable, so this file does nothing
# and MSVC keeps Opus' SIMD paths.

set(_xwin_toolchain "$ENV{CMAKE_TOOLCHAIN_FILE_x86_64_pc_windows_msvc}")
if(NOT _xwin_toolchain AND DEFINED ENV{XWIN_CACHE_DIR})
    # Older cargo-xwin, or a build driven by hand: fall back to the layout it
    # has always used inside the cache directory.
    set(_xwin_toolchain
        "$ENV{XWIN_CACHE_DIR}/cmake/clang-cl/x86_64-pc-windows-msvc-toolchain.cmake")
endif()

if(_xwin_toolchain AND EXISTS "${_xwin_toolchain}")
    include("${_xwin_toolchain}")

    # Opus (audiopus_sys) applies the per-file -msse4.1 / -mavx that its SIMD
    # sources need only `if(NOT MSVC)`, because real MSVC accepts those
    # intrinsics without a target-feature flag. clang-cl makes CMake set MSVC,
    # but is strict like GCC/Clang, so those files fail with "always_inline
    # function '_mm_cvtepi8_epi32' requires target feature 'sse4.1'".
    #
    # Turning the flag on globally would let the compiler emit SSE4.1/AVX in the
    # baseline code too, silently raising the CPU requirement of the whole app,
    # so instead drop just these dispatch paths. Opus still detects CPU features
    # at runtime and uses its C/SSE2 paths, which costs a fraction of a percent
    # of one core for 48 kHz voice. The native Windows build (MSVC) keeps them.
    set(OPUS_X86_MAY_HAVE_SSE4_1 OFF CACHE BOOL "disabled under clang-cl" FORCE)
    set(OPUS_X86_MAY_HAVE_AVX OFF CACHE BOOL "disabled under clang-cl" FORCE)
endif()
