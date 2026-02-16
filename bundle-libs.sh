#!/usr/bin/env bash
# Collect shared libraries for self-contained AppImage bundling.
# Called automatically by Tauri's beforeBundleCommand during ./build.sh.
#
# Traces ldd on the compiled binary, collects all .so dependencies
# (including transitive ones), and stages them in appimage-libs/.
# The build.sh TAURI_CONFIG maps this directory into AppDir/usr/lib/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STAGING="$SCRIPT_DIR/client/src-tauri/appimage-libs"

# Clean and recreate staging directory
rm -rf "$STAGING"
mkdir -p "$STAGING"

# Find the compiled binary (workspace target dir first, then crate-local)
BINARY=""
for candidate in \
    "$SCRIPT_DIR/target/release/voipc-client" \
    "$SCRIPT_DIR/client/src-tauri/target/release/voipc-client"; do
    if [ -f "$candidate" ]; then
        BINARY="$candidate"
        break
    fi
done
if [ -z "$BINARY" ]; then
    echo "[bundle-libs] ERROR: Binary not found. Searched:"
    echo "  $SCRIPT_DIR/target/release/voipc-client"
    echo "  $SCRIPT_DIR/client/src-tauri/target/release/voipc-client"
    echo "[bundle-libs] Run 'cargo build --release' first or let build.sh handle it."
    exit 1
fi

# --- EXCLUDE LIST ---
# Libraries that must come from the host system (always present, or GPU/display-specific).
# Based on AppImage excludelist + common sense for driver-coupled libs.
EXCLUDE_RE='linux-vdso\.so|ld-linux'
# Core C runtime (always present on every Linux system)
EXCLUDE_RE+='|libc\.so|libdl\.so|libm\.so|libpthread\.so|librt\.so'
EXCLUDE_RE+='|libutil\.so|libresolv\.so|libnss_|libthread_db\.so|libmvec\.so'
# C++ runtime (effectively always present)
EXCLUDE_RE+='|libgcc_s\.so|libstdc\+\+\.so'
# GPU drivers — must match the host's hardware
EXCLUDE_RE+='|libGL\.so|libEGL\.so|libGLdispatch\.so|libGLX\.so|libOpenGL\.so'
EXCLUDE_RE+='|libdrm\.so|libglapi\.so|libvulkan\.so'
EXCLUDE_RE+='|libgbm\.so'
# X11/Wayland core protocol — tightly coupled to display server
EXCLUDE_RE+='|libxcb\.so|libX11\.so|libX11-xcb\.so'
EXCLUDE_RE+='|libwayland-client\.so|libwayland-server\.so|libwayland-cursor\.so'
# D-Bus — system service
EXCLUDE_RE+='|libdbus-1\.so'
# Other low-level system libs
EXCLUDE_RE+='|libz\.so|libexpat\.so|libuuid\.so'

# --- FORCE-INCLUDE LIST ---
# Libraries that linuxdeploy's exclude list would skip but VoIPC needs.
# We collect them here so they end up in the AppImage regardless.
FORCE_LIBS=(
    "libpipewire-0.3.so"
    "libasound.so"
)

echo "[bundle-libs] Tracing library dependencies for: $BINARY"

# Collect all .so paths needed by the binary and their transitive deps (BFS)
collect_all_deps() {
    local binary="$1"
    declare -A seen
    local queue=()

    # Start with direct deps of the binary
    while IFS= read -r lib; do
        [ -n "$lib" ] && [ -f "$lib" ] && queue+=("$lib")
    done < <(ldd "$binary" 2>/dev/null | awk '/=>/ && $3 != "not" {print $3}')

    # Add force-include libs (may not be direct deps of the binary)
    for pattern in "${FORCE_LIBS[@]}"; do
        local found
        found=$(ldconfig -p 2>/dev/null | grep "$pattern" | awk '{print $NF}' | head -1)
        if [ -n "$found" ] && [ -f "$found" ]; then
            queue+=("$found")
        else
            echo "[bundle-libs] WARNING: Force-include lib '$pattern' not found on system" >&2
        fi
    done

    # BFS through the dependency tree
    local i=0
    while [ $i -lt ${#queue[@]} ]; do
        local lib="${queue[$i]}"
        ((i++))

        # Resolve to real path
        local real
        real=$(readlink -f "$lib" 2>/dev/null || echo "$lib")

        # Skip if already processed
        if [[ -v "seen[$real]" ]]; then
            continue
        fi
        seen["$real"]=1

        # Skip excluded libs
        local base
        base=$(basename "$real")
        if echo "$base" | grep -qE "$EXCLUDE_RE"; then
            continue
        fi

        # This lib should be bundled
        echo "$real"

        # Add its transitive deps to the queue
        while IFS= read -r dep; do
            [ -n "$dep" ] && [ -f "$dep" ] && queue+=("$dep")
        done < <(ldd "$real" 2>/dev/null | awk '/=>/ && $3 != "not" {print $3}')
    done
}

# Collect all library real paths
LIBS=$(collect_all_deps "$BINARY" | sort -u)

if [ -z "$LIBS" ]; then
    echo "[bundle-libs] WARNING: No libraries collected. AppImage may not be portable."
    exit 0
fi

# Copy each library and recreate symlink chains (soname resolution)
while IFS= read -r libpath; do
    [ -z "$libpath" ] && continue

    local_name=$(basename "$libpath")
    cp "$libpath" "$STAGING/$local_name"

    # Find symlinks pointing to this library and recreate them
    # (e.g., libfoo.so -> libfoo.so.1 -> libfoo.so.1.2.3)
    libdir=$(dirname "$libpath")
    for link in "$libdir"/*; do
        if [ -L "$link" ]; then
            target=$(readlink -f "$link")
            if [ "$target" = "$libpath" ]; then
                linkname=$(basename "$link")
                if [ "$linkname" != "$local_name" ]; then
                    ln -sf "$local_name" "$STAGING/$linkname"
                fi
            fi
        fi
    done
done <<< "$LIBS"

COUNT=$(find "$STAGING" -maxdepth 1 \( -type f -o -type l \) -name "*.so*" | wc -l)
SIZE=$(du -sh "$STAGING" | cut -f1)
echo "[bundle-libs] Staged $COUNT libraries/links ($SIZE) for AppImage bundling"
echo "[bundle-libs] Output: $STAGING"
