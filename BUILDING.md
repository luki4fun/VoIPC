# Building VoIPC

## Quick Setup

Setup scripts install all required tools and dependencies automatically:

```bash
# Linux (Ubuntu/Debian via apt, Arch via pacman)
./setup.sh

# Windows (PowerShell, run as Administrator)
.\setup.ps1
```

Then use the build scripts below.

---

## Linux

### System Dependencies (Ubuntu/Debian)

```bash
sudo apt-get install -y \
  libavcodec-dev \
  libavformat-dev \
  libavfilter-dev \
  libavdevice-dev \
  libavutil-dev \
  libswscale-dev \
  libx265-dev \
  libclang-dev \
  libturbojpeg0-dev \
  nasm \
  libpipewire-0.3-dev \
  libgbm-dev \
  libasound2-dev \
  libssl-dev \
  libgtk-3-dev \
  libwebkit2gtk-4.1-dev \
  libjavascriptcoregtk-4.1-dev \
  libsoup-3.0-dev \
  libayatana-appindicator3-dev
```

| Package | Required by |
|---------|-------------|
| `libavcodec-dev` | FFmpeg codec library (H.265/HEVC encoding/decoding) |
| `libavformat-dev` | FFmpeg container format support |
| `libavfilter-dev` | FFmpeg filter library |
| `libavdevice-dev` | FFmpeg device library |
| `libavutil-dev` | FFmpeg utility functions |
| `libswscale-dev` | FFmpeg pixel format conversion |
| `libx265-dev` | x265 HEVC encoder library |
| `libclang-dev` | libclang for bindgen (generates FFmpeg Rust bindings) |
| `libturbojpeg0-dev` | Fast JPEG encoding (screen share frame delivery) |
| `nasm` | SIMD assembly for libjpeg-turbo and x265 |
| `libpipewire-0.3-dev` | Screen capture via PipeWire ScreenCast |
| `libgbm-dev` | Screen capture (GBM buffer management) |
| `libasound2-dev` | Audio capture/playback (ALSA via cpal) |
| `libssl-dev` | TLS (rustls/ring) |
| `libgtk-3-dev` | Tauri window management |
| `libwebkit2gtk-4.1-dev` | Tauri webview |
| `libjavascriptcoregtk-4.1-dev` | Tauri webview JS engine |
| `libsoup-3.0-dev` | Tauri HTTP client |
| `libayatana-appindicator3-dev` | System tray icon (the app currently fails to start without the runtime lib) |

### System Dependencies (Arch / Manjaro / CachyOS)

```bash
sudo pacman -S --needed \
  ffmpeg x265 clang libjpeg-turbo nasm libpipewire mesa alsa-lib \
  openssl gtk3 webkit2gtk-4.1 libsoup3 libayatana-appindicator \
  curl base-devel
```

### Runtime Dependencies (for running the .deb on another machine)

The `.deb` package produced by `./build.sh` declares its dependencies, so `apt` will
install them automatically. If you distribute the raw binary instead, the target system
needs these **runtime** libraries (not the `-dev` packages):

```bash
sudo apt-get install -y \
  libavcodec60 \
  libavformat60 \
  libavutil58 \
  libswscale7 \
  libturbojpeg \
  libpipewire-0.3-0t64 \
  libgbm1 \
  libasound2t64 \
  libgtk-3-0 \
  libwebkit2gtk-4.1-0 \
  libjavascriptcoregtk-4.1-0 \
  libsoup-3.0-0 \
  libayatana-appindicator3-1
```

> **Note:** Package names with version suffixes (e.g. `libavcodec60`) vary between Ubuntu/Debian
> releases. The versions above match **Ubuntu 24.04 (Noble)**. On older or newer releases the
> soversion numbers may differ (e.g. `libavcodec58` on Ubuntu 22.04).

### Build Scripts

Use the provided scripts which set the required environment variables automatically:

```bash
./dev.sh          # Debug build + run (tauri dev)
./build.sh        # Release build (tauri build)
```

The scripts use the tauri CLI from the client's npm devDependencies (`npx tauri`) —
no global `cargo install tauri-cli` is required — and run `npm install` on first use.

### Environment Variables (if building manually)

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export BINDGEN_EXTRA_CLANG_ARGS="-I$(gcc -print-file-name=include)"
```

`BINDGEN_EXTRA_CLANG_ARGS` is needed because bindgen's bundled clang can't find GCC system headers (`stdbool.h`, etc.) without the explicit include path. `gcc -print-file-name=include` resolves the right directory on any distro; the build scripts set this automatically.

## Windows

### Prerequisites

1. **Rust** via [rustup](https://rustup.rs/) (select the MSVC toolchain)
2. **Visual Studio Build Tools** (or full Visual Studio) with the "Desktop development with C++" workload — provides MSVC compiler and Windows SDK
3. **Node.js** (for the Svelte frontend)
4. **CMake** — required by `libsignal-protocol` build ([cmake.org](https://cmake.org/download/))
5. **NASM** — required for SIMD optimizations in libjpeg-turbo and x265 ([nasm.us](https://www.nasm.us/))
6. **LLVM** — required by bindgen to generate FFmpeg Rust bindings (`winget install LLVM.LLVM`)
7. **FFmpeg** — installed via vcpkg (run `.\setup.ps1` to install automatically). Installed as `ffmpeg[x265,nvcodec,amf,qsv]` so the hardware H.265 encoders (NVIDIA NVENC, AMD AMF, Intel QuickSync) are compiled in. NVENC and AMF load from the GPU driver at runtime (no extra installs for users); QSV ships the Intel oneVPL dispatcher DLL with the app.

Make sure `cmake`, `nasm`, and LLVM are on your `PATH`. Or just run `.\setup.ps1` which handles all of the above.

If you set up FFmpeg with an older version of `setup.ps1` (without the HW encoder features), re-run `.\setup.ps1` — it detects the missing features and reinstalls FFmpeg.

### Screen sharing

Screen capture on Windows uses Windows.Graphics.Capture (displays and windows). Desktop audio is captured via WASAPI loopback.

### Build Scripts

```powershell
.\dev.ps1          # Debug build + run (cargo tauri dev)
.\build.ps1        # Release build (cargo tauri build)
```

### Building manually

```powershell
cd client
npm install
npx tauri dev      # Debug build + run
npx tauri build    # Release build
```

## Toolchain (all platforms)

- Rust via [rustup](https://rustup.rs/)
- Node.js (for the Svelte frontend)
- Tauri CLI: `npm install` in `client/`

## Android

```bash
./android-setup.sh    # one-time: installs SDK + NDK + JDK 21 + Rust targets to ~/android-sdk
./android-build.sh [debug|release] [--target aarch64|armv7|x86_64|all]
```

`android-setup.sh` bootstraps a fresh machine with no Android tooling: it
downloads the commandline-tools, accepts licenses, installs platform-tools,
the platform matching `compileSdk`, build-tools, the NDK, a bundled Temurin
JDK 21 (the Android Gradle plugin needs 17–21 — a too-new system Java won't
work), and the Rust cross-compile targets. Everything lands in `~/android-sdk`
(override with `ANDROID_HOME`); it is re-runnable and skips what's already
installed.

`android-build.sh` honors `ANDROID_HOME`, `ANDROID_NDK_HOME`, and `JAVA_HOME`
if set, otherwise auto-detects them (including the setup script's bundled JDK;
newest installed NDK wins) and tells you exactly what's missing. Release
builds need a `keystore.properties` at the repo root (copy
`keystore.properties.example`).

## Docker Release Build (AppImage)

Build portable release binaries inside Docker without installing any local dependencies:

```bash
./release.sh
```

This builds inside Ubuntu 24.04 and produces:
- `release/voipc-server` — static binary (musl, zero runtime deps)
- `release/VoIPC_*.AppImage` — portable client (runs on glibc >= 2.39)

Requires only Docker on the host. No Rust, Node.js, or system libraries needed.

To build the Docker image manually:

```bash
docker build -f Dockerfile.release -t voipc-release .
```

## Server

```bash
cargo build -p voipc-server --release
# Binary: target/release/voipc-server
```
