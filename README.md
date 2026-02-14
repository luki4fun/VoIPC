<p align="center">
  <br>
  <strong style="font-size: 2em;">VoIPC</strong>
  <br>
  <em>Privacy-first voice, video, and chat.</em>
  <br><br>
  <a href="#features">Features</a> &nbsp;&bull;&nbsp;
  <a href="#security">Security</a> &nbsp;&bull;&nbsp;
  <a href="#technology">Technology</a> &nbsp;&bull;&nbsp;
  <a href="#quick-start">Quick Start</a> &nbsp;&bull;&nbsp;
  <a href="#building">Building</a> &nbsp;&bull;&nbsp;
  <a href="#data-transparency">Data Transparency</a>
  <br><br>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/svelte-5-ff3e00.svg" alt="Svelte 5">
  <img src="https://img.shields.io/badge/tauri-2-24c8db.svg" alt="Tauri 2">
  <img src="https://img.shields.io/badge/encryption-Signal%20Protocol-green.svg" alt="Signal Protocol">
</p>

---

**VoIPC** is an encrypted, self-hosted voice/video/chat application. Think Discord or TeamSpeak, but with end-to-end encryption, zero data collection, and a server that never stores anything to disk.

No accounts. No telemetry. No compromises.

## Features

**Voice Chat**
- Opus codec at 48 kHz / 20ms frames / 48 kbps
- ML-based noise suppression (RNNoise via nnnoiseless)
- Voice Activity Detection with configurable threshold
- Push-to-Talk, VAD, and Always-On modes
- Forward Error Correction (15% packet loss tolerance)
- Per-user volume control

**Screen Sharing**
- H.265/HEVC encoding via FFmpeg
- Hardware acceleration: NVIDIA NVENC, Intel QSV, AMD AMF (libx265 software fallback)
- 480p / 720p / 1080p @ 30 fps
- Desktop audio capture
- Pop-out viewer window
- VPN-safe packet sizes (1280 bytes — fits inside WireGuard and OpenVPN tunnels)

**Text Chat**
- Channel and direct messages, both end-to-end encrypted
- Encrypted local chat history (password-protected, AES-256-GCM)
- Max 500 messages per channel stored locally

**Channels**
- Password-protected channels with invite system
- Per-channel media encryption keys
- Auto-cleanup of empty channels
- Configurable user limits

**Platform Support**

| | Linux | Windows | macOS |
|---|:---:|:---:|:---:|
| Voice | Yes | Yes | Yes |
| Screen Capture | PipeWire + XDG Portal | DXGI | Planned |
| Desktop Audio | PipeWire | WASAPI | Planned |

## Security

VoIPC encrypts everything at multiple layers. The server acts as a blind relay — it forwards encrypted packets without ever being able to read them.

### Layer 1: Transport — TLS on every connection

All TCP control traffic is encrypted with TLS 1.2+ via **rustls** (pure-Rust, no OpenSSL). TOFU (Trust-On-First-Use) certificate pinning is supported for self-signed server certs. Plaintext connections are never accepted.

### Layer 2: End-to-End Messages — Signal Protocol

Chat messages (channel and DM) use the **Signal Protocol** from the official [libsignal](https://github.com/nicklabs/libsignal) crate by Signal Foundation:

- **X3DH** (Extended Triple Diffie-Hellman) for session establishment
- **Double Ratchet** algorithm — new key for every message
- **Curve25519** identity keys (32-byte) with Ed25519 signed pre-keys
- **100 one-time pre-keys** per user, auto-replenished
- **Sender Keys** for efficient group/channel message encryption
- **Perfect Forward Secrecy** — a compromised key cannot decrypt past messages

### Layer 3: Media — AES-256-GCM on every packet

All voice, video, and screen share audio is encrypted with **AES-256-GCM** (via the `ring` crate):

- Per-channel 256-bit symmetric key, randomly generated
- Deterministic nonce: `session_id(4) || sequence(4) || extra(4)` — prevents reuse by construction
- 16-byte authentication tag on every packet — detects tampering
- AAD (Additional Authenticated Data) binds channel_id + packet_type — blocks cross-channel replay
- Mandatory key rotation after ~4.3 billion packets
- Media keys distributed to channel members encrypted via pairwise Signal sessions

### Layer 4: Local Storage — AES-256-GCM + PBKDF2

Client-side data at rest:

- Chat history encrypted with **PBKDF2-HMAC-SHA256** (600,000 iterations) + **AES-256-GCM**
- 32-byte random salt + 12-byte random nonce per file
- Signal Protocol state encrypted separately (VSIG file format)
- All secrets wrapped in `Zeroizing<T>` — memory-zeroized on drop

### Layer 5: Zero-Knowledge Server

- Server **never** sees plaintext messages (encrypted client-side)
- Server **never** stores chat history (no persistence, no disk writes)
- Server **never** decodes voice/video (SFU architecture — relays encrypted packets)
- Server **never** logs conversations (memory-only state, restart = clean slate)

### What the comparison looks like

| | VoIPC | Discord | TeamSpeak |
|---|---|---|---|
| E2E Encryption | Signal Protocol | No | No |
| Voice Encryption | AES-256-GCM | No | Limited |
| Self-Hosted | Yes | No | Yes |
| Open Source | MIT | No | No |
| Account Required | No | Yes | No |
| Data Collection | None | Extensive | Some |
| Server Persistence | None | Everything | Everything |
| Screen Share Codec | H.265 HW-accel | H.264/VP8 | Plugin |

## Technology

### Architecture

```
┌──────────────┐         TLS (TCP)          ┌──────────────┐         TLS (TCP)          ┌──────────────┐
│   Client A   │◄──────────────────────────►│    Server    │◄──────────────────────────►│   Client B   │
│  Tauri 2 App │   AES-256-GCM (UDP)        │  Rust Binary │   AES-256-GCM (UDP)        │  Tauri 2 App │
│  Rust+Svelte │◄──────────────────────────►│  Tokio SFU   │◄──────────────────────────►│  Rust+Svelte │
└──────────────┘                             └──────────────┘                             └──────────────┘
                                              Relays only —
                                              never decodes
```

- **TCP + TLS** for control messages (auth, channels, chat, encryption key exchange)
- **UDP** for real-time media (voice, video, screen share audio)
- **SFU** (Selective Forwarding Unit) — server relays encrypted packets without decoding

### Stack

| Layer | Technology | Details |
|---|---|---|
| **Audio** | Opus via audiopus | 48 kHz, mono, 20ms frames, 48 kbps, FEC, DTX |
| **Noise Suppression** | nnnoiseless (RNNoise) | ML-based, 480-sample frames at 48 kHz |
| **Video Codec** | H.265/HEVC via FFmpeg 8 | NVENC → QSV → AMF → libx265 fallback |
| **Encryption** | libsignal-protocol + ring | Signal Protocol for messages, AES-256-GCM for media |
| **TLS** | rustls 0.23 + ring | Pure-Rust TLS 1.2+, TOFU cert pinning |
| **Serialization** | postcard | Binary, no_std compatible, minimal overhead |
| **Server Runtime** | Tokio | Async, single-binary, DashMap lock-free concurrency |
| **Client Backend** | Tauri 2 (Rust) | Native IPC, audio/video/crypto all in Rust |
| **Client Frontend** | Svelte 5 + TypeScript | Runes ($state, $derived, $effect), Vite 6 |
| **Audio I/O** | cpal | ALSA (Linux), WASAPI (Windows), CoreAudio (macOS) |
| **Screen Capture** | Platform-native | PipeWire ScreenCast (Linux), DXGI (Windows) |

### Protocol Details

| Metric | Value |
|---|---|
| Voice packet header | 17 bytes (19 encrypted) |
| Video packet header | 23 bytes (25 encrypted) |
| Max voice packet | 512 bytes |
| Max video packet | 1,280 bytes (VPN-safe) |
| Max TCP message | 64 KiB |
| Protocol version | v3 |
| Default port | 9987 (TCP + UDP) |

### Project Structure

```
VoIPC/
├── crates/
│   ├── voipc-protocol/     # Message types, packet formats, codec
│   ├── voipc-server/       # Server binary (TCP + UDP + TLS)
│   ├── voipc-audio/        # Capture, playback, Opus, RNNoise, VAD, jitter buffer
│   ├── voipc-video/        # H.265 encoding/decoding, fragment assembly
│   └── voipc-crypto/       # Signal Protocol, AES-256-GCM, key management, persistence
├── client/
│   ├── src-tauri/src/      # Tauri Rust backend (network, crypto, state, commands)
│   │   ├── screenshare/    # Platform-specific capture (linux.rs, windows.rs)
│   │   ├── network.rs      # TCP/UDP connection handling, Signal session setup
│   │   ├── crypto.rs       # Chat history encryption (PBKDF2 + AES-256-GCM)
│   │   ├── app_state.rs    # Central app state (connections, audio, crypto)
│   │   └── commands.rs     # Tauri IPC command handlers
│   └── src/
│       ├── lib/
│       │   ├── components/ # 15 Svelte 5 components
│       │   └── stores/     # Reactive state (channels, chat, voice, etc.)
│       └── App.svelte      # Root component
├── website/                # Project website (single HTML file)
├── setup.sh / setup.ps1    # One-command dependency installer
├── build.sh / build.ps1    # Release build scripts
├── dev.sh / dev.ps1        # Dev build + run
└── Cargo.toml              # Workspace root
```

## Quick Start

### Server

```bash
# Build
cargo build -p voipc-server --release

# Generate self-signed TLS certificate
mkdir -p certs
openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout certs/server.key -out certs/server.crt \
  -days 365 -nodes -subj "/CN=voipc"

# Run
./target/release/voipc-server
```

The server listens on port **9987** (TCP + UDP) by default. Configure via `server.toml`:

```toml
tcp_port = 9987
udp_port = 9987
max_users = 64
cert_path = "certs/server.crt"
key_path = "certs/server.key"
```

Runtime settings in `server_settings.json`:

```json
{
  "empty_channel_timeout_secs": 300,
  "max_channels": 50,
  "max_channel_name_len": 32
}
```

### Client

```bash
# Linux
./setup.sh    # Install system dependencies
./build.sh    # Release build

# Windows (PowerShell as Administrator)
.\setup.ps1
.\build.ps1
```

Or manually:

```bash
cd client
npm install
npx tauri dev     # Dev build + run
npx tauri build   # Release build
```

See [BUILDING.md](BUILDING.md) for detailed platform-specific instructions and dependency lists.

## Data Transparency

### What the server stores (in memory only)

- Active usernames and channel memberships
- Channel names, descriptions, passwords (`Zeroizing<String>` — cleared on drop)
- Connection metadata (IP addresses while connected)
- Media encryption keys per channel (`Zeroizing<[u8; 32]>`)
- Pre-key bundles for Signal session establishment

**Nothing is written to disk. Server restart = complete clean slate.**

### What the server never sees

- Message contents — encrypted with Signal Protocol before leaving your device
- Voice/video content — encrypted with AES-256-GCM before transmission
- Chat history — stored only on your device, encrypted
- Your private keys — only public keys are exchanged

### What your device stores

- Encrypted chat history (`VOIP` binary format, password-protected)
- Encrypted Signal Protocol state (`VSIG` binary format)
- Audio/video settings and device preferences
- Max 500 messages per channel, auto-rotated

### What is never stored anywhere

- No analytics or telemetry
- No user accounts or profiles
- No server-side message logs
- No tracking of any kind
- No third-party data sharing

## Contributing

VoIPC is MIT licensed. Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `cargo build --workspace` to verify everything compiles
5. Submit a pull request

## License

[MIT](LICENSE)

---

<p align="center">
  <em>Built with Rust, Svelte, and paranoia.</em>
  <br>
  <sub>No cookies. No tracking. Not even on this README.</sub>
</p>
