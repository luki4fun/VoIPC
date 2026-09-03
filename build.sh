#!/usr/bin/env bash
# Release build (tauri build)
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# bindgen (FFmpeg/PipeWire bindings) needs the compiler's own include dir;
# its location differs per distro, so ask gcc instead of hardcoding it
if command -v gcc >/dev/null; then
  GCC_INCLUDE="$(gcc -print-file-name=include)"
  [ -d "$GCC_INCLUDE" ] && export BINDGEN_EXTRA_CLANG_ARGS="-I$GCC_INCLUDE"
fi

# Sync version from workspace Cargo.toml → tauri.conf.json & package.json
VERSION=$(grep -m1 '^version' "$SCRIPT_DIR/Cargo.toml" | sed 's/.*"\(.*\)"/\1/')
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$SCRIPT_DIR/client/src-tauri/tauri.conf.json"
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$SCRIPT_DIR/client/package.json"

# The tauri CLI comes from the client's npm devDependencies — no global install needed
cd "$SCRIPT_DIR/client"
[ -d node_modules ] || npm install
exec npx tauri build "$@"
