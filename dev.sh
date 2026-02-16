#!/usr/bin/env bash
# Debug build + run (cargo tauri dev)
export PATH="$HOME/.cargo/bin:$PATH"
export BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/13/include"

# Sync version from workspace Cargo.toml → tauri.conf.json & package.json
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION=$(grep -m1 '^version' "$SCRIPT_DIR/Cargo.toml" | sed 's/.*"\(.*\)"/\1/')
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$SCRIPT_DIR/client/src-tauri/tauri.conf.json"
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$SCRIPT_DIR/client/package.json"

exec cargo tauri dev "$@"
