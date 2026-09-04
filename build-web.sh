#!/usr/bin/env bash
# Web client build: wasm crate (Signal + protocol + media crypto) + Vite bundle,
# then a release server binary that embeds the bundle and serves it over HTTP/2.
# Output: release/VoIPC-web-<version>.tar.gz (static bundle, for hosting elsewhere)
#         target/release/voipc-server (serves the embedded web client)
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Sync version from workspace Cargo.toml → package.json (APP_VERSION must match the server)
VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" client/src-tauri/tauri.conf.json
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" client/package.json

if ! rustup target list --installed | grep -q '^wasm32-unknown-unknown$'; then
  echo "=== Installing Rust target wasm32-unknown-unknown ==="
  rustup target add wasm32-unknown-unknown
fi

echo "=== Building web client $VERSION (wasm + Vite) ==="
cd client
[ -d node_modules ] || npm install
npm run build:web
cd ..

echo "=== Building server with the embedded web client ==="
cargo build -p voipc-server --release

mkdir -p release
tar -czf "release/VoIPC-web-$VERSION.tar.gz" -C client dist-web

echo ""
echo "=== Web client artifacts ==="
echo "Static bundle:  release/VoIPC-web-$VERSION.tar.gz"
echo "Server binary:  target/release/voipc-server (serves https://<host>:9987/)"
