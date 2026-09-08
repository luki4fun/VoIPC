# Building VoIPC

## Quick Setup

Setup scripts install all required tools and dependencies automatically:

```bash
# Linux (Ubuntu/Debian via apt, Arch via pacman)
./setup.sh

# Windows (PowerShell, run as Administrator)
.\setup.ps1
```

Then use the commands below.

---

## Command reference

Everything runs from the repo root as `npm run <task>`, on Linux and Windows
alike. `node tools/voipc.mjs --help` lists the tasks. Arguments after `--` pass
straight through to the underlying tool.

### Release builds

| Command | Builds | Output |
|---|---|---|
| `npm run build` | desktop client for the current OS | Linux: `target/release/bundle/{deb,appimage}/` · Windows: `target/release/bundle/nsis/` |
| `npm run build:windows` | Windows client, cross-compiled from Linux | `target/x86_64-pc-windows-msvc/release/` + `bundle/nsis/` |
| `npm run web` | wasm + Vite bundle, then the server that embeds it | `target/release/voipc-server`, `release/VoIPC-web-<v>.tar.gz` |
| `npm run android -- release` | signed APK (needs `keystore.properties`) | `release/VoIPC-android-release.apk` |
| `npm run release` | all Linux artifacts in Docker, portable | `release/` — AppImage, musl server, web bundle |

Everything at once, in the same versions a release ships: push a `v*` tag and
let `.github/workflows/release.yml` build all four platforms.

### Demo builds (a default server in the connect dialog)

`VITE_DEFAULT_SERVER=host[:port]` bakes a server into the connect dialog, so a
build handed to someone starts pointing at your relay. The port defaults to
9987; an IPv6 literal goes in brackets (`[2001:db8::1]:9987`).

```bash
VITE_DEFAULT_SERVER=demo.example.org npm run build            # desktop
VITE_DEFAULT_SERVER=demo.example.org npm run web              # web bundle + server
VITE_DEFAULT_SERVER=demo.example.org npm run android -- release
npm run release -- --build-arg VITE_DEFAULT_SERVER=demo.example.org   # Docker
```

Leave it unset for a normal release: the dialog then starts at `localhost:9987`
in the desktop app and at the page's own origin in the browser. The release
workflow takes the same value as the optional `default_server` input when you
run it by hand from the Actions tab; tag builds never set it.

### Debug builds

| Command | Notes |
|---|---|
| `npm run dev` | debug build **and run** the desktop client |
| `npm run build -- --debug` | debug build without running — lands in `target/debug/` |
| `npm run web -- --debug` | debug server binary at `target/debug/voipc-server` |
| `npm run android -- debug` | unsigned debug APK — no keystore needed |

`npm run build:windows` and `npm run release` are release-only. A debug Windows
cross build would need the real debug CRT, which cannot be shipped and is
deliberately stubbed out (see the cross-compiling section).

### Other

| Command | Purpose |
|---|---|
| `npm run test:web` | headless two-browser end-to-end check |
| `npm run version:sync` | propagate the `Cargo.toml` version everywhere |
| `npm run version:check` | fail if any copy has drifted (used by CI) |
| `npm run setup:windows` | one-time cross-build toolchain |
| `npm run setup:android` | one-time Android SDK/NDK/JDK |

Useful flags: `--bundles deb`, `--bundles nsis,msi` to pick installer formats;
`VOIPC_NO_BUNDLE=1` to skip the Windows installer.

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
| `libx265-dev` | x265 HEVC encoder library (H.264 comes with libavcodec's libx264) |
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
| `libayatana-appindicator3-dev` | System tray icon (optional at runtime: without the library there is no tray and closing the window quits) |

### System Dependencies (Arch / Manjaro / CachyOS)

```bash
sudo pacman -S --needed \
  ffmpeg x265 clang libjpeg-turbo nasm libpipewire mesa alsa-lib \
  openssl gtk3 webkit2gtk-4.1 libsoup3 libayatana-appindicator \
  curl base-devel
```

### Runtime Dependencies (for running the .deb on another machine)

The `.deb` package produced by `npm run build` declares its dependencies, so `apt` will
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

Every build task runs through one command, identically on Linux and Windows:

```bash
npm run dev            # Debug build + run
npm run build          # Release build (deb + AppImage)
```

These set the required environment variables automatically, use the tauri CLI
from the client's npm devDependencies (`npx tauri`) — no global
`cargo install tauri-cli` — and run `npm install` on first use.
`node tools/voipc.mjs --help` lists every task. Arguments after `--` are passed
straight through, e.g. `npm run build -- --bundles deb`.

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
4. **CMake** — builds the vendored Opus (`audiopus_sys`) and libjpeg-turbo (`turbojpeg-sys`) ([cmake.org](https://cmake.org/download/))
5. **NASM** — required for SIMD optimizations in libjpeg-turbo and x265 ([nasm.us](https://www.nasm.us/))
6. **LLVM** — required by bindgen to generate FFmpeg Rust bindings (`winget install LLVM.LLVM`)
7. **protoc** — required by the `libsignal-protocol` build (`winget install Google.Protobuf`)
8. **FFmpeg** — installed via vcpkg (run `.\setup.ps1` to install automatically). Installed as `ffmpeg[x264,x265,nvcodec,amf,qsv]` so both software encoders and the hardware ones (NVIDIA NVENC, AMD AMF, Intel QuickSync) are compiled in for H.264 and H.265. NVENC and AMF load from the GPU driver at runtime (no extra installs for users); QSV ships the Intel oneVPL dispatcher DLL with the app.

Make sure `cmake`, `nasm`, `protoc`, and LLVM are on your `PATH`. Or just run `.\setup.ps1` which handles all of the above.

The build defaults `VCPKG_ROOT` to `C:\Program Files\vcpkg` but honours a pre-set
value, which is how the CI workflow points it at the runner's own vcpkg. The CMake
generator is detected through vswhere rather than hardcoded, so a machine on a
newer Visual Studio than 2022 still builds.

If you set up FFmpeg with an older version of `setup.ps1` (without the HW encoder features), re-run `.\setup.ps1` — it detects the missing features and reinstalls FFmpeg.

### Screen sharing

Screen capture on Windows uses Windows.Graphics.Capture (displays and windows). Desktop audio is captured via WASAPI loopback.

### Build Scripts

```powershell
npm run dev            # Debug build + run
npm run build          # Release build (NSIS installer)
npm run build -- --bundles nsis,msi   # both installer formats
```

### Building manually

```powershell
cd client
npm install
npx tauri dev      # Debug build + run
npx tauri build    # Release build
```

## Windows: cross-compiling from Linux

You can build the Windows client on a Linux machine with no Windows install, VM,
Wine or Proton involved. `clang-cl` and `lld-link` are native Linux binaries that
speak the MSVC ABI; [cargo-xwin](https://github.com/rust-cross/cargo-xwin)
downloads the Microsoft CRT and Windows SDK, and FFmpeg comes from a prebuilt
Windows build instead of vcpkg (vcpkg cannot build `x64-windows` ports off Windows).

```bash
npm run setup:windows   # one-time: toolchain, NSIS, prebuilt Windows FFmpeg
npm run build:windows   # release build + NSIS installer
```

Output:

- `target/x86_64-pc-windows-msvc/release/voipc-client.exe`
- `target/x86_64-pc-windows-msvc/release/bundle/nsis/VoIPC_<version>_x64-setup.exe`

### Prerequisites

```bash
# Arch
sudo pacman -S --needed clang lld llvm ninja cmake nasm protobuf unzip curl
paru -S nsis          # AUR — the NSIS installer bundler

# Debian/Ubuntu
sudo apt install clang lld llvm ninja-build cmake nasm protobuf-compiler unzip curl nsis
```

`npm run setup:windows` checks all of these, adds the `x86_64-pc-windows-msvc`
Rust target, installs `cargo-xwin`, and downloads FFmpeg. On first build
cargo-xwin fetches ~600 MB of Microsoft CRT/SDK into `~/.cache/cargo-xwin`. By
using it you accept the [Microsoft license](https://go.microsoft.com/fwlink/?LinkId=2086102);
that cache is **not redistributable**, so never commit or ship it.

### Environment knobs

| Variable | Default | Purpose |
|---|---|---|
| `VOIPC_FFMPEG_WIN64` | `~/.local/share/voipc/ffmpeg-win64` | Where the Windows FFmpeg lives |
| `VOIPC_FFMPEG_ASSET` | `ffmpeg-n8.1-latest-win64-gpl-shared-8.1.zip` | Which [BtbN build](https://github.com/BtbN/FFmpeg-Builds/releases) to fetch |
| `VOIPC_NO_BUNDLE` | unset | Set to `1` to build just the `.exe` (skips needing NSIS) |
| `VOIPC_TURBOJPEG_WIN64` | unset | Point at a prebuilt libjpeg-turbo if the vendored CMake build fails |
| `XWIN_CACHE_DIR` | `~/.cache/cargo-xwin` | Where the MSVC CRT/SDK is cached |

The FFmpeg build must be a **`-shared`** one (those ship `include/` and the MSVC
`lib/*.lib` import libraries) and must match the FFmpeg major that `ffmpeg-next`
targets — currently FFmpeg 8.x / libavcodec 62. The GPL variant is required for
`libx264` and `libx265`; like the vcpkg build it also has NVENC, AMF and QSV
compiled in.

### Differences from a native Windows build

- **NSIS installers only.** MSI needs WiX, which only runs on Windows. Use the
  GitHub Actions workflow below for MSI.
- **Opus loses its SSE4.1/AVX paths.** Opus only applies the per-file `-msse4.1`
  those sources need `if(NOT MSVC)`, and clang-cl sets `MSVC` while still
  requiring the flag. `xwin-msvc-toolchain.cmake` disables those dispatch paths
  rather than enabling SSE4.1 globally, which would silently raise the app's CPU
  requirement. Opus falls back to its C/SSE2 paths; the cost is a fraction of a
  percent of one core for 48 kHz voice.
- **The installer is unsigned**, same as the native build.
- **Untestable on Linux:** WASAPI audio, Windows.Graphics.Capture, and the
  NVENC/AMF/QSV encoders. WebView2 also does not work under Wine, so `wine
  voipc-client.exe` only proves the binary loads and finds its DLLs.

### Verifying the build

```bash
# Every non-system DLL listed here must be in client/src-tauri/external-dlls/
llvm-readobj --coff-imports target/x86_64-pc-windows-msvc/release/voipc-client.exe |
    grep -oiE '[A-Za-z0-9_.-]+\.dll' | sort -fu

# Run the Windows unit tests under Wine
WINEDEBUG=-all WINEPATH="$HOME/.local/share/voipc/ffmpeg-win64/bin" \
    cargo xwin test --release --target x86_64-pc-windows-msvc \
    -p voipc-protocol -p voipc-crypto -p voipc-audio
```

## Releases (GitHub Actions)

`.github/workflows/release.yml` builds every artifact and opens a **draft**
release for review. Push a tag to run it, or dispatch it manually from the
Actions tab to rehearse without tagging:

```bash
git tag v0.5.0 && git push origin v0.5.0
```

It refuses to build if the tag and `[workspace.package] version` disagree, or if
any copy of the version has drifted — the server compares version strings for
exact equality, so a mismatched release ships clients that every server rejects.
Release notes come from the matching `## [x.y.z]` section of `CHANGELOG.md`.

| Job | Runner | Produces |
|---|---|---|
| `linux` | ubuntu-24.04 | AppImage, `.deb`, static musl server, web bundle |
| `windows` | windows-2025 | NSIS `.exe` and `.msi`, plus a real-Windows smoke test |
| `android` | ubuntu-24.04 | signed APK |

The repository is public, so all of this runs on free standard runners. The
Windows job caches the vcpkg FFmpeg build, which otherwise takes 1-4 hours on a
2-core runner; MSI installers can only be produced there, since WiX is
Windows-only.

### Android signing secrets

The Android job is skipped unless these repository secrets exist
(Settings → Secrets and variables → Actions):

| Secret | Value |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | `base64 -w0 voipc-release.jks` |
| `ANDROID_KEYSTORE_PASSWORD` | the keystore password |
| `ANDROID_KEY_ALIAS` | the key alias, e.g. `voipc` |
| `ANDROID_KEY_PASSWORD` | the key password |

The job writes them back into a `keystore.properties` and keystore at the repo
root, builds, and deletes both afterwards.

## Toolchain (all platforms)

- Rust via [rustup](https://rustup.rs/)
- Node.js (for the Svelte frontend)
- Tauri CLI: `npm install` in `client/`

`Cargo.lock` (both the workspace's and `crates/voipc-web`'s) and
`client/package-lock.json` are committed: a tag has to build the same
dependency versions a year from now. `npm run version:sync` keeps the npm
lockfile's own version field in step with `Cargo.toml`.

## Android

```bash
npm run setup:android   # one-time: SDK + NDK + JDK 21 + Rust targets in ~/android-sdk
npm run android -- [debug|release] [--target aarch64|armv7|x86_64|all]
```

`setup:android` bootstraps a fresh machine with no Android tooling: it
downloads the commandline-tools, accepts licenses, installs platform-tools,
the platform matching `compileSdk`, build-tools, the NDK, a bundled Temurin
JDK 21 (the Android Gradle plugin needs 17–21 — a too-new system Java won't
work), and the Rust cross-compile targets. Everything lands in `~/android-sdk`
(override with `ANDROID_HOME`); it is re-runnable and skips what's already
installed.

The build honors `ANDROID_HOME`, `ANDROID_NDK_HOME`, and `JAVA_HOME` if set,
otherwise auto-detects them (including the setup task's bundled JDK; newest
installed NDK wins) and tells you exactly what's missing.

### Release signing

Release builds need a keystore and a `keystore.properties` at the repo root.
Both are gitignored and must never be committed. To create them:

```bash
# keytool ships with the JDK; setup:android puts one in ~/android-sdk/jdk/bin
keytool -genkeypair -v \
  -keystore voipc-release.jks \
  -alias voipc \
  -keyalg RSA -keysize 4096 \
  -validity 10000 \
  -storetype PKCS12

cp keystore.properties.example keystore.properties
# then set storePassword and keyPassword to what you just chose
# (PKCS12 uses one password for both)
```

> **Escape backslashes in the passwords.** Gradle reads this file with
> `java.util.Properties`, where `\` is an escape character — a password
> containing `a\b` must be written `a\\b`. An unescaped one silently yields a
> different string and the build fails with *"keystore password was
> incorrect"*, even though the password is right.

> **Losing a keystore is permanent.** Android identifies an app by its signing
> key, so an APK signed with a new key cannot be installed as an update over one
> signed with the old key — users have to uninstall the old app first, which
> wipes its local data. Back this file up somewhere durable.

For CI, the same material goes in as repository secrets — see the release
workflow section below.

## Web client (browser)

```bash
npm run web         # wasm crate + Vite bundle + server binary that embeds it
npm run test:web    # headless two-browser end-to-end check
```

`npm run web` installs the `wasm32-unknown-unknown` Rust target if missing, builds
`crates/voipc-web` with `wasm-pack` (a client devDependency, no global install), bundles the
Svelte app in web mode to `client/dist-web`, and then builds the server, which embeds that
directory with `rust-embed`. Outputs:

- `target/release/voipc-server` — serves the web client at `https://<host>:<tcp_port>/`
- `release/VoIPC-web-<version>.tar.gz` — the static bundle, if you want to host it elsewhere

The wasm crate is a separate Cargo workspace (`crates/voipc-web`), because it replaces
`pqcrypto-kyber` with a stub (its C code cannot build for wasm and VoIPC never negotiates
Kyber) and enables wasm-only features of `getrandom` and `ring`. Nothing of that leaks into
the native build.

Manual steps, if you prefer:

```bash
cd client
npm install
npm run build:wasm   # wasm-pack → client/src/lib/wasm
npm run build:web    # wasm + vite build --mode web → client/dist-web
npm run dev:web      # dev server on http://localhost:1420 (point it at a running server)
cd .. && cargo build -p voipc-server --release
```

The web end-to-end test starts a server on test ports with a throwaway certificate, runs two headless
browsers with a fake microphone through the in-page self-test, and checks that they see each
other, exchange the media key over Signal, hear each other's voice, read each other's channel
messages and DMs, and that one watches the other's screen share (an animated canvas stands in
for the display, so no real capture is needed). Set `CHROME=/path/to/chrome` if Chromium is not
on `PATH`.

```bash
npm run test:web                                  # Chromium on both sides
BROWSER=firefox ./test-web.sh                     # Firefox on both sides
BROWSER_ALICE=chromium BROWSER_BOB=firefox ./test-web.sh   # Chromium shares H.264, Firefox watches
BROWSER_ALICE=firefox BROWSER_BOB=chromium ./test-web.sh   # Firefox shares VP9, Chromium watches
```

The Firefox lane needs `certutil` (Arch: `nss`, Debian/Ubuntu: `libnss3-tools`) to trust the
test certificate.

## Docker Release Build (AppImage)

Build portable release binaries inside Docker without installing any local dependencies:

```bash
npm run release
```

This builds inside Ubuntu 24.04 and produces:
- `release/voipc-server` — static binary (musl, zero runtime deps), serving the embedded web client
- `release/VoIPC_*.AppImage` — portable client (runs on glibc >= 2.39)
- `release/VoIPC-web-*.tar.gz` — the web client bundle (already inside the server binary)

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
