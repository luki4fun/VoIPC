# Changelog

All notable changes to VoIPC are documented here.

## [0.4.0] - 2026-09-02

### Changed — screen share encoding performance
- **Windows builds now include hardware H.265 encoders** — vcpkg FFmpeg is installed as `ffmpeg[x265,nvcodec,amf,qsv]`, enabling NVIDIA NVENC, AMD AMF, and Intel QuickSync (previously every Windows user encoded on the CPU with libx265). NVENC/AMF load from the GPU driver at runtime; QSV ships the Intel oneVPL dispatcher DLL. Re-run `.\setup.ps1` to pick up the new features
- Encoder rate control: VBV (`maxrate`/`bufsize`) is now set on all encoders so keyframes stay under the 316 KB UDP fragmentation ceiling (previously oversized keyframes were truncated, corrupting the stream); hardware encoders get an explicit 2-second GOP instead of the FFmpeg default IDR-every-12-frames; `forced-idr` ensures app-requested keyframes are real IDRs; libx265 `keyint` follows the actual frame rate instead of hardcoded 30
- Fixed Intel QuickSync producing no video: the frame converter now outputs the encoder's pixel format (NV12 for QSV) instead of always YUV420P
- Fixed keyframes being silently discarded on Linux under send backpressure — `Handle::try_current()` fails on the dedicated encode thread, so the fragments were dropped and the viewer stayed frozen. The encode thread now waits for channel room in a loop that stays interruptible by the shutdown flag, so a congested uplink cannot outlive a stop/switch and strand the pipeline
- Linux capture now paces to the requested frame rate — compositors running at high refresh (e.g. 144 Hz) no longer drive capture/encode at full refresh for a 30 fps share
- Windows capture loop paces at the top of the loop, so capture errors no longer busy-spin at 100% CPU
- Frame converter is rebuilt when the source resolution changes (window resize / portal renegotiation no longer garbles or crops the stream)
- Capture buffers are recycled between capture and encode threads (previously the steady state allocated a full frame per capture, ~110 MB/s at 1080p30)
- The media-key mutex is no longer held across fragment/encrypt/send, removing a contention path that could stall voice while sharing
- 60 fps shares get +50% bitrate (previously 60 fps used the same bitrate as 30, halving per-frame quality)
- Server per-session video rate limit raised from 120 pkt/s (~1.2 Mbps — silently dropped most of a 3–5 Mbps stream and caused keyframe-request storms) to 1200 pkt/s burst 400 (~12 Mbps ceiling); note this raises the per-session UDP forwarding ceiling accordingly
- `pipewire` crate bumped 0.8 → 0.10 (0.8 fails to build against libclang ≥ 19)

### Changed — voice pipeline & network resilience
- **Clocked voice mixer** — remote voice and screen-share audio are now decoded and mixed on a 20 ms clock (per-user jitter buffer → Opus decode → per-user gain × master volume → single playback ring) instead of each UDP packet racing to push PCM directly into playback. Fixes garbled audio when several people talk at once and gives screen-share audio jitter/reorder protection
- **Opus in-band FEC** — a lost voice packet is now reconstructed from the FEC data carried by the packet that follows it, falling back to packet-loss concealment only when the next packet is also missing
- **Adaptive jitter buffer** — buffering delay grows under observed late packets (40 ms → up to 160 ms) and decays after quiet periods; sender-restart and large sequence jumps resync quickly instead of playing seconds of concealment noise
- **Audio device hot-recovery** — capture and playback streams are rebuilt automatically when a device dies (unplugged headset, default device change); the UI shows an error toast while retrying and a restored toast on success. Output device changes now apply live without reconnecting
- **Non-48 kHz devices work** — capture and playback resample to/from the device rate (previously such devices played pitch-shifted audio or failed); WASAPI loopback screen-share audio is resampled too
- **NAT rebind** — the server re-learns a session's UDP address when its NAT mapping expires and reopens on a new port (previously voice died until a full reconnect); a UDP keepalive every 10 s keeps mappings alive through silent channels
- **Real latency display** — the ping shown in the status bar is now a true UDP round-trip on the media path (previously it compared the server's clock against the client's, showing clock skew)
- Voice nonce sequence persists across PTT presses (an AES-GCM nonce could previously repeat after a restart of the counter)
- Server relays voice packets without re-parsing the payload and no longer holds the channel lock across sends (a join/leave can no longer stall voice for everyone)
- Speaking indicators are edge-triggered (one event per talk burst instead of one per packet)

### Security
- **Fixed AES-GCM nonce reuse across media streams** — voice, screen-share audio, and video encrypt under the same channel key but kept independent sequence counters, so talking while screen-sharing produced identical key+nonce pairs on different plaintexts. The packet-type byte now domain-separates the nonce, and screen-share frame/audio counters persist across shares instead of restarting at 0. Old and new clients cannot decrypt each other's media — update all clients together
- Server caps keyframe requests at ~1/s per viewer (previously a viewer could force ~50 IDRs/s onto a sharer via the generic message budget)

### Added — UI
- **Saved servers** — the connect dialog keeps a list of saved servers (★ Save); click an entry to connect
- **Fullscreen screen-share viewing** — button or double-click, in both the in-app viewer and the pop-out window
- **Microphone test** — level meter in Settings → Audio Input, works without joining a call
- Errors are now surfaced as toasts (connection-loss reason, kick/shutdown message, device/channel/chat failures) instead of silently landing in the console
- Auto-reconnect keeps trying for 5 minutes (was 30 seconds) — survives Wi-Fi roams and laptop sleep; Cancel still available

### Added — quality of life
- **System tray** — closing the window now hides to the tray and the call keeps running; tray menu offers Show/Hide, Toggle Mute, Toggle Deafen, and Quit (Quit actually exits)
- **Desktop notifications** — DMs and pokes show an OS notification while the window is unfocused (first launch asks for permission); DMs also flash the taskbar like pokes
- **Global mute/deafen hotkeys** — optional system-wide hotkeys (Settings → Global Hotkeys) that work while unfocused or in the tray, using the same evdev/rdev machinery as PTT
- **Mic input gain** — capture-side gain slider (0–400%) next to the output volume; applies live, also visible in the settings mic test
- **Voice quality indicator** — the status bar shows packet-loss percentage next to the ping (colored: <1% normal, 1–5% orange, ≥5% red), fed by the jitter buffer's conceal counts
- **Dead-UDP detection** — if keepalive Pongs stop for 35 s while TCP stays up, a sticky warning explains that voice/UDP is blocked (firewall/NAT) instead of silent mute/deafness; clears itself on recovery
- **Chat next to screen share** — watching a share no longer replaces the chat: it appears in a collapsible pane under the video (desktop)
- **Copyable links in chat** — URLs in messages are highlighted; clicking opens a copy dialog with the URL preselected (links never open a browser directly)
- **Skippable chat vault** — the first-run encrypted-history setup can be skipped ("don't save chat history"); chat then stays in memory only. Re-enable under Settings → Data
- **E2E identity warning** — if a contact's encryption identity key changes (potential impersonation), a sticky warning names the user and stays until dismissed
- Version-mismatch errors now say which version the server runs and that the client needs updating

### Fixed
- Dropdown menus rendered with a native white background and gray text on Linux — WebKitGTK ignores themed `<select>` styling unless `appearance: none` is set; all selects now render dark with a custom chevron
- The client crashed on startup when no appindicator library was installed (libappindicator-sys panics on load) — the tray is now optional: without it the app logs a warning and closing the window quits instead of hiding to tray
- The client crashed on NVIDIA + Wayland ("Gdk Error 71 dispatching to Wayland display") — WebKitGTK's DMA-BUF renderer is now disabled by default (`WEBKIT_DISABLE_DMABUF_RENDERER=1`, overridable via the environment)
- `setup.sh`/`build.sh`/`dev.sh` only worked on Ubuntu/Debian: setup.sh now also supports pacman (Arch), the build scripts use the npm-installed tauri CLI (`npx tauri`) instead of requiring a global `cargo tauri`, and the bindgen include path is derived from `gcc -print-file-name=include` instead of a hardcoded Debian path; `release.sh` fails fast with a clear message when docker is missing
- `android-build.sh` had another machine's SDK path hardcoded (`ANDROID_HOME=/home/lukas/...`) plus a Debian-only `JAVA_HOME` and a global `cargo tauri` dependency — it now honors `ANDROID_HOME`/`ANDROID_NDK_HOME`/`JAVA_HOME` from the environment, auto-detects them from common install locations (newest installed NDK wins), uses the npm-installed tauri CLI, errors clearly when something is missing, and parses `debug|release`/`--target` in any order; it also sets `CMAKE_POLICY_VERSION_MINIMUM=3.5` so libopus configures under CMake 4
- **Added `android-setup.sh`** — one-command Android bootstrap for a fresh machine: installs commandline-tools, platform + build-tools (following `compileSdk` from the tauri-generated gradle file), the pinned NDK, a bundled Temurin JDK 21, accepts licenses, and adds the Rust cross-compile targets; re-runnable, everything env-overridable
- **Added the missing `ndk-arm64-toolchain.cmake`** — `android-build.sh` always referenced it but the file was never committed, so Android builds failed on any machine but the original one (libopus configured with no compiler); it's a thin wrapper over the NDK's official toolchain pinning `arm64-v8a` / `android-26`

## [0.3.0] - 2026-04-19

### Added
- **Android app** (Tauri 2 Mobile) — full mobile client: Oboe audio capture with RNNoise, `VoiceService` foreground service, volume-key PTT, tabbed mobile UI, `MobilePTT.svelte`, speakerphone toggle, and `android-build.sh` producing universal debug/release APKs
- **Persistent channels** — server can load a `channels.json` defining long-lived rooms (name, description, password, max_users); plaintext `password` fields are SHA-256-hashed on first load and the file is rewritten atomically (`channels.example.json`, `crates/voipc-server/src/channels.rs`)
- **TOFU certificate pinning** — `TofuCertVerifier` in the client pins self-signed cert fingerprints per host on first connect
- **IPv6 support** — client address parser accepts `[host]:port`, rustls `ServerName` uses `IpAddress` for IP literals, server UDP socket binds dual-stack when `host` is IPv6
- **XDG-compliant data directory** — `settings.json` and `chat_history.bin` moved to `~/.config/VoIPC/` (Linux) / `%APPDATA%/VoIPC` (Windows); legacy files next to the executable are migrated on first launch (fixes AppImage where the exec dir changes on every run)
- **Chat history setup flow** — `ChatHistorySetup.svelte` + configurable `chat_history_path`, so users can pick where the encrypted archive lives
- **Server connection limits** — global cap (256) and per-IP cap (5) on TCP connections
- **UDP rate limiting (server)** — per-session token-bucket rate limiters on voice and video packets
- **Graceful shutdown (server)** — Ctrl-C broadcasts `ServerShutdown` to all connected clients before the accept loop exits
- **Android runtime permission prompts** — `RECORD_AUDIO` requested at startup; JS-side toast feedback on denial via `__voipc_permission_denied`
- **Security audit documents** — `audit-desktop-todo.md`, `audit-server-todo.md`, `audit-android-todo.md` tracking findings and fixes

### Changed
- UDP address-cache hits now re-verify `udp_token` on every packet (closes spoof-based session hijack); sessions are bound first-address-wins
- Sender-key and media-key distribution verify both sender and recipient are channel members before the server relays
- `TofuCertVerifier` keys the pin store by canonical lowercase DNS name or standard IP string instead of the rustls `Debug` format (cross-version stable)
- Video packet parser rejects `fragment_index >= fragment_count`, zero-fragment packets, and unknown packet types
- Frame assembler and jitter buffer use wraparound-safe distance checks for `u32` sequence / frame-id overflow
- PTT "held" detection re-verifies the main key (not just modifiers) and the Linux evdev loop re-enumerates devices when keyboards are hot-plugged
- Signal Protocol tracking state is cleared on disconnect and reset on reconnect (prevents stale sessions from surviving a reconnect)
- Windows WGC screen capture now reuses the staging D3D11 texture across frames and only reallocates when dimensions/format change
- Opus encoder returns an error instead of panicking when the PCM frame size is wrong
- Config directory creation falls back to the OS temp dir instead of panicking when `~/.config` is unavailable
- Poisoned-mutex recovery (warn + `into_inner()`) applied consistently across client-side locks
- Android `MainActivity` sets `MODE_NORMAL` + speakerphone on by default for VoIP calls; `network_security_config.xml` restricts cleartext traffic

### Fixed
- IPv6 literal addresses were rejected by the old `host:port` splitter
- Chat history and settings were lost on AppImage upgrades because the exec dir changes each run
- Various DM/poke edge cases around reconnect — Signal state was not cleared, causing sender-key mismatches on re-established sessions

## [0.2.0] - 2026-02-16

### Added
- **Poking** — encrypted poke notifications, with popup UI and sound alert
- **Config persistence** — all settings saved to `settings.json` in the VoIPC data directory (`~/.config/VoIPC/` on Linux, `%APPDATA%/VoIPC` on Windows)
- **Configurable notification sounds** — per-action enable/disable and volume control for channel switch, user join/leave, messages, pokes, and disconnect
- **Auto-reconnect** — exponential backoff with visual reconnection overlay on connection loss
- **Docker release build** — `Dockerfile.release` and `release.sh` produce a static server binary (musl) and portable AppImage client
- **UI overhaul** — centralized icon system (`Icons.svelte`), design tokens in CSS, redesigned VoiceControls, UserList, ChatPanel, ChannelList, and SettingsPanel components
- **Server-client version check** — server validates client `app_version` during handshake and rejects incompatible clients
- **Global Push-to-Talk keybind** — PTT hotkey via `rdev` crate works system-wide, even when the app window is unfocused; configurable from settings
- **Windows screen capture improvements** — desktop/window source picker UI, hot-swap source selection, fix for GPU adapter mismatch in DXGI capture

### Fixed
- Receiving DMs and pokes in channel 0 (off-by-one in channel membership check)

### Changed
- Removed plaintext `SendChannelMessage` and `SendDirectMessage` protocol variants — all messages are now exclusively end-to-end encrypted
- Added `SendPoke` / `PokeReceived` protocol messages (encrypted via Signal Protocol)
- Added `app_version` field to the protocol handshake message
- Build scripts updated (`build.sh`, `build.ps1`, `dev.sh`, `dev.ps1`)

## [0.1.0] - 2026-02-15

Initial public release.
