#!/usr/bin/env bash
# Debug build + run (cargo tauri dev)
export PATH="$HOME/.cargo/bin:$PATH"
export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/13/include"

exec cargo tauri dev "$@"
