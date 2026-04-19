# Changelog

All notable changes to VoIPC are documented here.

## [0.3.0] - Unreleased

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