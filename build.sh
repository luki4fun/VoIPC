#!/usr/bin/env bash
# Release build (cargo tauri build)
export PATH="$HOME/.cargo/bin:$PATH"
export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/13/include"

exec cargo tauri build "$@"
