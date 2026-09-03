#!/usr/bin/env bash
# Build portable release binaries inside Docker.
# Output: release/voipc-server (static) + release/VoIPC_*.AppImage
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v docker &>/dev/null; then
  echo "release.sh builds inside Docker and requires the docker CLI." >&2
  echo "Install docker (or use ./build.sh for a native build) and retry." >&2
  exit 1
fi

# Sync version
VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" client/src-tauri/tauri.conf.json
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" client/package.json

echo "=== Building VoIPC $VERSION release ==="

IMAGE="voipc-release"
docker build -f Dockerfile.release -t "$IMAGE" .

# Extract binaries from the scratch image (--entrypoint needed for scratch images)
mkdir -p release
CONTAINER=$(docker create --entrypoint /bin/true "$IMAGE")
docker cp "$CONTAINER":/ - | tar --strip-components=0 -xf - -C release/ \
    --exclude='dev' --exclude='etc' --exclude='proc' --exclude='sys'
docker rm "$CONTAINER" >/dev/null

echo ""
echo "=== Release artifacts ==="
ls -lh release/
echo ""
echo "Server (static): release/voipc-server"
echo "Client AppImage: release/VoIPC_*.AppImage"
