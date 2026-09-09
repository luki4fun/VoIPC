# Changelog

All notable changes to VoIPC are documented here.

## [0.7.0] - unreleased

Protocol version 7 — client and server must be updated together (a channel now carries a proximity mode and four options, and positions travel as a new encrypted media packet). A 0.5.x client connecting to a 0.7 server is told to update and stops reconnecting.

### Added — channel options

Four options per channel, in `channels.json` or through the channel's gear icon (its creator, or an admin; channels from `channels.json` have no creator, so those are admin-only). They are what an ingame roleplay channel needs, and they compose: see the `Ingame` entry in [channels.example.json](channels.example.json).

- **`hidden`** — the channel is not listed for anyone but admins. It can still be joined through an invite link or by the game SDK, so it is out of the way rather than locked
- **`anonymous`** — members see each other as `Guest-1234`, a fresh name each time they enter. **The substitution happens on the server**, in every message that carries a name: the member list, joins, chat, direct messages, pokes, invites and screen-share notices. No other client is ever told the real name, and you see your own pseudonym too, so you know what the others see. Admins see the real names, which is what makes moderating such a channel possible. Chat history is not handed over in an anonymous channel: the names in an archive sit inside the ciphertext, where the server cannot substitute them
- **`screen_share`** — `false` refuses sharing in that channel, and the button disappears there
- **`hide_members`** — non-admins get no member list and no head count, only whoever is speaking (for about ten seconds), so a voice can still be turned down without the room being a roster. Members still receive the list internally, because the encryption keys are exchanged per member

### Fixed

- A refused screen share no longer leaves the sharer permanently marked as sharing. The flag was set before the channel was even looked up, so any later refusal locked that session out of sharing until reconnect

### Added — proximity chat

- **A channel can place voices in space.** Its mode is `off`, `2d` (a floor plan) or `3d` (height counts too), chosen when the channel is created and changeable afterwards by its creator — or by an admin, which is also the only way to change a channel from `channels.json`, exactly as with their password. Set `"proximity": "2d"` on an entry in `channels.json` to have a room start that way
- **Voices are panned and attenuated on the receiving client**: the constant-power pan law browsers use for `StereoPannerNode`, the inverse distance model FMOD and TeamSpeak 3 use, Mumble's near-field bloom so someone standing on you does not spin around your head, and a fade over the last stretch of the range so a voice crossing it does not click. Gains ramp across each 20 ms frame; a source nobody placed sounds exactly as it did before, at unity on both channels
- The formula lives once per host — `crates/voipc-audio/src/spatial.rs` and `client/src/lib/spatial.ts` — and both assert the same golden table, so the desktop and the browser cannot drift apart. The browser check runs in the end-to-end test
- **The playback path is stereo end to end.** A mono output device gets the downmix, a surround device the front pair. **Android plays the downmix for now**: distance works there, panning does not
- **A virtual room** shows the channel on a top-down plan (plain SVG, no new dependency). Arrange everyone yourself and the layout stays on your machine; turn on *Sync my position* and you move only yourself while your position is broadcast to the channel. Presets: round table, class room with a presenter at the front, line, free placement. In a `3d` channel each avatar gets a height slider
- **Positions are as private as voice.** A shared position is one 39-byte AES-256-GCM packet under the channel key, relayed like a voice datagram: the server sees that a member is sharing a position and nothing else. It is re-sent once a second so a late joiner converges, at most ten times a second while moving, and the server drops it entirely in a non-proximity channel
- **Per-viewer choice for screen-share audio**: it can come from where the sharer stands or stay centred, toggled in the viewer's toolbar or in Settings. Spatial audio as a whole can be switched off per client, which matters on a mono headset or with hearing in one ear
- **A server-wide switch**: `proximity_enabled: false` in `server_settings.json` serves every channel as non-positional, refuses requests to enable it, and stops relaying positions
- **Try it without a second person**: Settings → Spatial Audio → *Test 2D* / *Test 3D* sends a synthetic voice circling you through the real mixer, with a live readout of where it is. Turning "Hear people where they stand" off while it runs is the A/B comparison. On desktop it needs a connection (it plays through the call's mixer); Android hears the distance but not left/right

### Added — a game SDK, as the open alternative to the TeamSpeak plugins

- **A game mod can drive the positions.** VoIPC opens a loopback WebSocket that a page inside the game runtime connects to, the way SaltyChat, YACA and TokoVOIP work — but with no plugin to install, no license server, and players addressed by their VoIPC user id instead of by matching nicknames
- One bulk update a few times a second carries the listener's pose and every audible player with their range, volume override, 0–10 muffling and mode. A player left out of the list is silent, which is how distance culling works in the plugins scripts already target. Radio, phone and megaphone audio is `mode: "radio"`, `"phone"` or `"direct"`, and the handshake's `capabilities` list says what a build actually renders
- **Radio and phone are real effects now**, not flat audio: `mode: "phone"` band-limits a voice to roughly 300–3400 Hz, and `mode: "radio"` adds drive, a faint hiss and a short squelch burst when a transmission starts and ends. Deterministic and click-free; the browser client has no SDK and renders both flat, which is what `capabilities` is for
- **Positions glide between updates.** A mod sending 4–10 times a second used to step the pan and the volume at exactly that rate; each player (and the listener's own pose and facing) now moves smoothly over the gap between updates. A jump of more than 50 m snaps instead, so a respawn does not sweep across the room
- **VoIPC pushes back**: `talk` for another player starting or stopping, `self` for the local player's speaking, mute and deafen, `user` for someone else's mute. Enough for a talking icon over a player's head. "Speaking" means voice actually going out, so push-to-talk and mute are reflected
- **`hello` now waits for the join.** It used to answer `ingame` before the channel was joined, so a wrong password looked like success and left distance culling armed with nobody driving it. A refusal is relayed verbatim: `could not join Ingame: incorrect channel password`
- **Off by default**, loopback only, and origins are checked: the game runtimes are allowed by prefix, `localhost` and `127.0.0.1` only as the exact host, and everything else is refused — a page served from `localhost.example.com` is an ordinary internet page that can reach a local port like any other. `hello.server` is required, so a mod cannot skip the wrong-server check by leaving it out, and the newest connection that completed a handshake owns the mix: a refused or stale socket can no longer clear a running game's positions on its way out
- After a VoIPC reconnect the mod's player ids belong to the previous session; VoIPC answers such an update with an error telling it to say hello again, instead of silently culling every speaker out of the mix
- **Hardened the socket**: a handshake must finish in 5 seconds, a silent socket is closed after 30, at most four are served at once, `Upgrade` and `Sec-WebSocket-Version: 13` are checked, client frames must be masked as the standard requires, and a first frame pipelined behind the upgrade request is no longer thrown away. A port that cannot be bound is reported in Settings instead of leaving the toggle on and nothing listening
- **A ready-made FiveM resource** in `sdk/fivem-voipc/`: state-bag identity, head-bone positions at 10 Hz, distance culling, muffling from vehicles, interiors and line of sight, and a voice-range key. Radio, phone and the talking overlay are left as documented stubs. `sdk/test-page.html` grew the channel field, the radio and phone modes, the build's capability list and a live "who is talking" line
- `docs/SDK.md` documents the protocol and the FiveM/alt:V/RAGE identity flow

### Fixed — hardening of the above, before it ships

- **The web client no longer wedges when a channel is created.** The session cached the channel-list array it also handed to the UI, so a later in-place update duplicated a channel; Svelte's keyed list threw inside its flush and every later update threw again, leaving the window dead. The event bus now hands out copies, and both list updates replace instead of appending blindly, which also covers the server's snapshot and broadcast racing on two simultaneous joins
- **Proximity chat now works on the desktop client at all**: the mixer only learned a channel's mode from the channel list and from later edits, never from joining one, so voices stayed flat and no position was ever shared. Joining also drops the previous room's placements, as the browser already did
- **Changing a channel's proximity no longer deletes its password.** Saving the settings dialog always rewrote the password with the empty field; it is now left alone unless you type one or tick *Remove the password*
- A dragged avatar sends at most ten positions a second on both clients, instead of one per pointer event — most of which the server dropped, the resting position among them
- A newly created mixer source no longer bursts at full volume for its first 20 ms: gains start at their target instead of ramping down from unity, so a locally muted or distant speaker stays quiet
- The browser client applies the saved spatial-audio settings on load, ignores non-finite positions (one NaN silenced a source for good), and the room view no longer keeps sharing your position after *Reset*, leaves a stale selection behind when someone leaves, or shows *Sync my position* as on when the toggle failed
- The room view now locks while a game drives the positions, which the game SDK had announced since the beginning with nobody listening

### Fixed — Android

- **A channel can be joined on a phone at all.** Joining is a double click, and the page is zoomable, so Android read a double tap as double-tap-to-zoom and never delivered the event — you could highlight a channel and nothing else. The channel row now opts out of that gesture
- **The Android build compiles again.** `tauri::Manager` was imported only on desktop, and the new game-SDK event publishers use it everywhere; nothing had compiled the Android target since that landed, because no CI job does. Verified end to end this time: built, installed on a phone, connected to a 0.7.0 server, joined a channel

### Fixed — older bugs, while we were in here

- **Muting or deafening yourself shows on your own row at once.** The marker in the member list only appeared after a channel switch, because the server deliberately does not send `UserMuted` back to the session that caused it and no client filled the gap; the toolbar button looked right the whole time, which is what made it confusing. Toggling from the Android notification now updates the button as well, which it never did
- **Firefox can share a screen or a window again.** The browser client asked for the shared screen's audio unconditionally, and Firefox — which has never implemented that capture (Mozilla bug 1541425) — answers by offering browser tabs and nothing else. It is no longer asked for there, and the share dialog says why and points at a Chromium browser for anyone who needs the sound

### Changed — build tooling

- `npm run release` no longer stops dead when Docker is missing. It falls back to a host build of the web bundle and the server, names the AppImage as the artifact it had to skip and says why it is worth having (the image exists to pin glibc 2.39 so one build runs everywhere), and warns that the host server is not the static musl one. `VOIPC_NO_DOCKER=1` takes that path on purpose
- The artifact summary lists what the run actually built. It used to print the whole `release/` directory, so last month's tarball was reported as fresh output
- `npm run version:check` now also covers the FiveM resource manifest and the two copies of the SDK's `state` example, which had been drifting by hand

### Fixed — CI, which had never finished a release

- **The Windows release job is the build that actually works.** It built natively on a Windows runner against FFmpeg from vcpkg — a path that shared no code with `npm run build:windows` and had never once succeeded. vcpkg follows FFmpeg head and is on 9.0.1; `ffmpeg-sys-next` 8.1 stops at libavcodec 62, so every attempt compiled for eight minutes and then died in the bindings, after a forty-minute FFmpeg build that a failing job never got to keep. Windows is now cross-built on Linux by the same task run at home, with FFmpeg pinned to 8.1 and its ABI major checked before anything compiles against it, and a small Windows job installs the resulting installer and checks the app starts. Only NSIS is built; the MSI bundle had never been produced anywhere
- **The Rust test job installs the client's dependencies.** `npm --prefix client test` was added as "no dependencies to install", which stopped being true when the store tests landed: they reach `svelte/store` through `room.ts` and `users.ts`, so on a runner's fresh checkout the step died instantly on `ERR_MODULE_NOT_FOUND`
- **`clang-cl` is no longer assumed.** Arch ships that name, Debian and Ubuntu ship only `clang` — and clang picks its cl driver mode from `argv[0]`, so the cross build links one itself instead of failing its tool check on a distribution it should support
- **Caches survive a failed job.** `actions/cache` only saves on success, which is why every red Windows run threw away the expensive part and started over; the caches that guard a long download or build now restore and save separately
- **A red build says what went wrong.** Reading Actions logs through the API needs admin rights on the repository even when it is public, so a failure was a black box to anyone without push access. Every build and test step now runs through `tools/ci-run.sh`, which repeats the tail of a failure as an annotation — those need no credentials at all. `test-web.sh` has done this for its browser lanes since 0.5.2
- **The Opus SIMD workaround reaches the build again.** `xwin-msvc-toolchain.cmake` disables Opus' SSE4.1/AVX dispatch paths, which clang-cl refuses to compile without a target-feature flag, and it was selected through an environment variable whose name contains dashes. That is not a valid shell identifier: `dash` drops such variables from the environment it passes on and `bash` keeps them, so the override survived on Arch (`/bin/sh` is bash) and silently vanished on an Ubuntu runner (`/bin/sh` is dash) — Opus then compiled its SSE4.1 sources and the Windows build died with four errors nobody could see. It now comes from `.cargo/config.toml`'s `[env]`, which cargo puts straight into the build script's environment with no shell in between, and the wrapper finds cargo-xwin's own toolchain through the variable cargo-xwin itself sets instead of reassembling the path. The Android task already used the underscored spelling and was never affected
- **The Windows smoke test looks where the installer actually puts the app.** It was carried over verbatim from the native-Windows job, which was skipped on every run it ever had, so it had never executed once: it looked for `VoIPC.exe` under `%LOCALAPPDATA%\Programs\VoIPC`, while Tauri's NSIS installs in currentUser mode to `%LOCALAPPDATA%\VoIPC\voipc-client.exe`. It now reads the install location and binary name back out of the uninstall key the installer writes, so it stays correct if those defaults change, and reports any failure as an annotation the way the Linux side does. Launching the installed app is reported but does not fail the job yet — nothing has yet observed a Tauri window surviving on a runner session

### Testing

- The spatial maths is asserted along a full 2D and 3D trajectory in both languages, not just at a few fixed points, and the browser copy is checked in the end-to-end run
- `npm test` in `client/` runs the browser-side unit tests on Node's own runner (no new dependency)
- `test-ui.mjs` drives the real Svelte UI in a headless browser — creating a proximity channel, arranging the room, joining with a second client, changing the mode — and fails on any uncaught error. The end-to-end script runs it in its Chromium lanes; it reproduces the wedging bug above on the unfixed code

## [0.5.2] - 2026-09-08

Protocol version 5 — client and server must be updated together (one QUIC connection per client, media headers without the UDP token, loss reports, the share's codec). A 0.4 client that connects to a 0.5.2 server is told to update and stops reconnecting, and so is a build from the unreleased 0.5.0/0.5.1 trees: they speak protocol 5 but without the codec field, which the server checks by exact version match.

### Added — screen sharing in every browser

- **Any browser can watch a screen share.** A share now states its codec (`StartScreenShare`), the server hands it to each viewer when they start watching, and the viewer builds its decoder from that. Desktop sharers encode **H.264 by default**, which every client decodes — Firefox included, and Chromium on Linux, neither of which has ever had an HEVC decoder in WebCodecs. H.265 stays available under Settings → Screen Share for rooms where everyone watches from a desktop client; a viewer that cannot decode a share's codec is told which codec it is and that the sharer can switch, instead of being left with a black frame
- **Browsers can share their screen.** `getDisplayMedia` → WebCodecs → the same encrypted fragments the desktop client sends, one QUIC stream per frame. VoIPC picks the codec by actually encoding a frame with it: Chromium shares H.264, Firefox falls back to VP9 because its WebCodecs H.264 encoder reports support and then refuses to encode ([Bugzilla 1918769](https://bugzilla.mozilla.org/show_bug.cgi?id=1918769)). Desktop audio comes along where the browser offers a track (Chromium for tabs and system audio; Firefox on Linux offers none). The frame clock runs in a Worker, so a share keeps its frame rate while the tab sits in the background — where a sharer's tab lives, and where page timers are throttled to about one tick per second
- The browser share honours the same viewer-count gating, keyframe requests and quality ladder as the desktop sharer, and drops a frame rather than sending one too big for the 255-fragment wire format (WebCodecs has no VBV)
- Encoders and decoders are wired for H.264, H.265, VP8 and VP9 across all three clients — FFmpeg on the desktop, MediaCodec on Android, WebCodecs in browsers
- **The end-to-end browser test now shares and watches a screen.** `BROWSER_ALICE` / `BROWSER_BOB` pick the engine per side, so one run covers Chromium sharing to Firefox and the next covers the reverse; all four pairings pass. An animated canvas stands in for the display, so headless runs need no real capture
- Windows builds now install FFmpeg with `x264` alongside `x265` (`.\setup.ps1`, and the cached vcpkg build in CI); Linux gets libx264 with the distribution's libavcodec

### Added — a default server for demo builds

- `VITE_DEFAULT_SERVER=host[:port]` at build time pre-fills the connect dialog, so a build handed to someone points at your relay from the start. Unset — as in every tagged release — the dialog starts at `localhost:9987` in the desktop app and at the page's own origin in the browser. Works for the desktop, web, Android and Docker builds; the release workflow takes it as an optional `default_server` input when run by hand (see BUILDING.md)

### Changed — native clients over QUIC
- **Desktop and Android clients now connect over QUIC (WebTransport), the endpoint the browser client already used.** The TCP control connection and the raw UDP media socket are gone: control messages travel on one bidirectional stream, voice and screen-share audio as QUIC datagrams, and every video frame on its own unidirectional stream — in both directions, so the server relays the same thing for every client. TLS 1.3 only
- **One UDP port for everyone.** The QUIC endpoint listens on `udp_port` (default 9987, same number as the page's TCP port); `web_port` and UDP 9988 are gone (an old `server.toml` with `web_port` still loads, the key is ignored). Native clients ask for the operator certificate by TLS server name and pin it on first use exactly as before — existing pins keep working; browsers keep getting the short-lived hash-pinned certificate on the same endpoint
- **NAT rebind, keepalive and dead-UDP detection replaced by QUIC.** Connection migration survives NAT mapping changes and address changes (Wi-Fi roams), keepalives are QUIC's, and a blocked UDP port now fails the connect with a clear error instead of leaving a session that is silently mute and deaf. The `udp_token` / address-learning machinery, the loopback bridge for browser sessions and the dead-UDP toast are removed; the status-bar latency comes from QUIC's own RTT estimate
- **Media headers shrink by 8 bytes** (voice 17 → 9, video 23 → 15, screen audio 21 → 13 plus 2 for the key id when encrypted): the UDP token they carried no longer exists. The server checks that a packet's session id is the sending connection's own instead
- Disconnecting closes the QUIC connection explicitly so the server frees the username immediately
- The `voice_load` example drives QUIC clients and sends encrypted voice (it used to send plaintext, which the server drops); the TCP `test_client` example is gone

### Added — screen-share congestion control
- **Viewers report frame loss to the sharer every 2 s** (native and browser viewers alike) and the sharer steps its encoder down a ladder — 60%, 40% and 25% of the configured bitrate, with the frame rate halved on the two lowest rungs — instead of answering loss with ever more keyframes. A sharer whose own uplink queue backs up counts that as loss too. After 30 s without loss it climbs one rung back. Level changes are logged
- **Only a majority of the viewers steps a share down.** Reports are counted over a 2 s window against the current viewer count, so one viewer on a bad link (or one lying about it) no longer costs everybody else quality
- **The sharer also watches its own QUIC path**, which viewer reports cannot see: once a second it compares lost packets against packets sent and the round-trip time against the session's minimum, and treats ≥1% loss or a doubled RTT as congestion. The send queue is half as deep as before (about a second of video), so backpressure is reported sooner instead of hiding a growing backlog
- Keyframe requests are now capped per share rather than per viewer: one relayed request per second however many viewers ask, which ends the keyframe storms a crowded share used to trigger

### Changed — screen-share bandwidth and latency
- **A periodic keyframe every 4 s instead of every second**, roughly a quarter less video bandwidth at 1080p30. Video travels on reliable QUIC streams, where loss no longer breaks the decoder chain, so the periodic keyframe is only a safety net — and every viewer joining a share now gets one on the spot (still at most one per second per share), rather than only the first
- **Video fragments are relayed and decoded as they arrive.** The server and both clients used to read a whole frame's stream before parsing it, so every hop added the frame's full transmission time — 35 ms for a delta frame and up to 300 ms for a keyframe on a 5 Mbps link

### Security
- **A QUIC connection slot is only spent once the client's address is validated.** The slot used to be taken on the first packet and held for the whole 10 s handshake window, so spoofed source addresses could pin all 256 of them and lock everyone out. Unvalidated sources now get a Retry first, which costs one extra round trip on a first connect

### Fixed — Android
- **The Android app started and immediately died.** The native library needs the NDK's C++ runtime (the audio layer is C++) but never declared it, and Android's loader resolves only what a library declares — so `dlopen` failed with `cannot locate symbol "__cxa_pure_virtual"` before the first screen was drawn. Shipping `libc++_shared.so` inside the APK was not enough. The build now links it, and the Android build task refuses to package a library that does not
- **Watching a screen share showed "Waiting for video stream..." forever.** Frames were being received and decoded the whole time; the viewer converted them to RGBA and the JPEG encoder rejects an alpha channel ("does not support the color type `Rgba8`"), so every frame was dropped on the way to the screen. It converts to RGB now
- **A share that was not a multiple of 16 wide decoded sheared or stretched.** The decoder is configured before the first frame with a 1920x1080 guess, and on a device that does not report a stride, that guess survived as the row stride of a 720p picture. The stride now follows the real size, and the codec's crop rectangle is applied, so a 854-wide share is shown as 854 and not as the padded 864
- The connect dialog on Android and Windows offered `tauri.localhost` as the server, the app's own internal webview origin. It offers `localhost` again; only the browser client fills in the page's origin

### Fixed
- **A kicked or banned client is told why again.** Ending a session waited for whichever of its legs finished first, and on a kick that is always the media relay, so the control leg was cut off while it was still delivering the reason. The client showed a plain "connection lost" instead of the kick message, most of the time in Firefox and occasionally in Chromium
- Screen-share and voice relay no longer take a detour through a loopback UDP socket for browser sessions
- The web client says so when the browser has no WebCodecs audio decoder, instead of staying silent as if nobody were talking; the H.265 probe also accepts the `hvc1` spelling of the codec, which some browsers advertise instead of `hev1`
- Firefox is now covered by the browser end-to-end test (`BROWSER=firefox ./test-web.sh`): voice, chat, direct messages, invites, history and admin kick all pass on Firefox 155

## [0.4.0] - 2026-09-04

Protocol version 4 — client and server must be updated together (client-generated media keys, nonce domain separation).

### Added — web client
- **VoIPC runs in the browser.** Point a browser at `https://your-server:9987` and you get the same app: channels, voice, E2E chat, DMs, pokes, and screen-share viewing. No install, no extension. The server binary embeds the web client, so hosting it is not a separate deployment
- **Same crypto as the native clients** — the Signal Protocol (libsignal) and AES-256-GCM media encryption are compiled to WebAssembly and run in the page. The server relays the same encrypted bytes it relays for desktop clients and can read no more than before
- **HTTP/2 and WebTransport, no HTTP/1** — the page is served over HTTP/2 on the existing TLS port; control messages travel on one WebTransport (QUIC) stream and media as QUIC datagrams, with each video frame on its own stream. The TLS listener now offers only `h2` to browsers, so HTTP/1 requests are refused during the handshake. The WebTransport endpoint listens on UDP `web_port` (default 9988; `0` disables the web client) with a short-lived certificate the server generates and rotates itself and publishes by hash to the page — operators configure nothing beyond opening the port
- **Browser media pipeline** — Opus encode/decode and H.265 decode via WebCodecs, capture and mixing in AudioWorklets with the same 20 ms clock and jitter buffer as the native mixer. Where a browser cannot decode H.265 (Linux browsers today) watching a share says so instead of showing a black frame; voice and chat work everywhere
- **Not in the web client:** sharing your own screen, the pop-out viewer, global hotkeys, the tray, and the encrypted chat vault (browser chat is in-memory only). Everything else is the desktop feature set. Needs Chrome 97+, Edge 98+, Firefox 130+ or Safari 26.4+ (WebTransport and WebCodecs)
- Notification sounds in the browser: built-in tones per event (Settings → Sounds), no files needed; phones other than Android (iPhone, iPad) get the mobile layout
- `build-web.sh` builds it (wasm + Vite + server), `test-web.sh` runs a headless two-browser end-to-end check of voice, chat, DMs, invite links, history hand-off and an admin kick, and `./release.sh` now also emits `release/VoIPC-web-<version>.tar.gz`

### Added — moderation without accounts
- **Admin sessions.** Any connected user can log in with the server's admin token (status bar → shield). Set `admin_token` in `server.toml`, pass `--admin-token`, or export `VOIPC_ADMIN_TOKEN`; without one the server prints a fresh random token in its log at every start (like a TeamSpeak privilege key). Admins are visible to everyone (shield badge), can kick users from any channel or from the server, and ban an IP for 1 h, 24 h or until restart. Bans live in server memory only, apply to TCP and WebTransport connections alike, and can be lifted from the admin panel. Three wrong tokens disconnect the session
- Kicks and bans carry a reason; the client shows it and does not auto-reconnect afterwards

### Added — onboarding
- **Invite links**: `https://your-server:9987/#channel=<name>[&password=…]`. Opened in a browser it lands in the web client with the channel pre-selected and joins it right after connecting; the desktop connect dialog accepts the same link. The fragment never leaves the browser (not sent to the server, not in its logs). *Copy invite link* sits in the channel-list header; the password rides along when your session knows it, otherwise the joiner is asked
- **Channel history for newcomers**: on joining a channel, one member hands you the last 50 channel messages over your pairwise Signal session (end-to-end; the server relays ciphertext between members only). They appear above a "shared by …" divider and are deduplicated against what you already have. Opt out under Settings → Data. Direct messages are never shared

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
- Version-mismatch errors now say which version the server runs and that the client needs updating

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
- Connect has a 10 s deadline per phase (TCP, TLS, auth) — a black-holed host no longer pins the reconnect loop and its Cancel button for minutes
- The TCP reader times out after 150 s without data (two missed server pings), so a silently dead path (Wi-Fi roam, laptop sleep, NAT expiry) triggers auto-reconnect instead of a frozen session
- The UDP receiver survives `recv` errors (Windows reported `WSAECONNRESET` after any ICMP unreachable and voice died for the rest of the session)
- Concurrent connects (reconnect loop vs. manual connect) are serialized; the loser's tasks no longer leak
- A second `connection-lost` during a reconnect (server shutdown is followed by the socket closing) no longer hides the reconnect overlay while the retry loop keeps running; cancelling a reconnect discards an attempt that was already in flight
- Signal state is reset on every connect. Identities are ephemeral by design; keeping the store across a server restart made libsignal reject peers whose reassigned user id had belonged to someone else
- TOFU pins are keyed by `host:port` (two self-signed servers on one machine no longer read as a MITM of each other) and can be forgotten from the connect dialog after a legitimate certificate change
- Server per-IP connection cap raised from 5 to 10: a browser holds two slots (the HTTP/2 page connection and the WebTransport session), so the old cap allowed only two web users behind one NAT

### Security
- **Media keys never touch the server.** Until now the server generated every channel's AES-256-GCM key and sent it to each joiner over TLS, so a server operator could decrypt all voice, video and screen-share audio despite the "blind relay" claim. The first member of a channel now generates the key on the client; existing members hand it to each joiner over their pairwise Signal session (`DistributeMediaKey`, which the server relays without being able to read). The server-issued `ChannelMediaKey` message is gone. Re-keying when a member leaves is not implemented yet (the server stops relaying to them; on-path capture of later packets would still decrypt) — planned as a follow-up
- **Fixed AES-GCM nonce reuse across media streams** — voice, screen-share audio, and video encrypt under the same channel key but kept independent sequence counters, so talking while screen-sharing produced identical key+nonce pairs on different plaintexts. The packet-type byte now domain-separates the nonce, and screen-share frame/audio counters persist across shares instead of restarting at 0. Old and new clients cannot decrypt each other's media — update all clients together
- **No plaintext media, ever.** Voice, video and screen audio were sent unencrypted whenever no media key was installed (e.g. the moment after a channel switch in voice-activation mode), and receivers accepted plaintext packet types even with a key present. Senders now drop frames until a key is installed (the UI shows a warning if that takes more than 2 s) and both the server relay and the client receiver drop the plaintext types
- **UDP source check on the client.** The receiver accepted datagrams from any address; anyone who learned the client's endpoint could inject packets or spoof keepalive replies. Only packets from the server's UDP address are processed
- **Relay no longer leaks `udp_token`.** Every forwarded voice/video packet carried the sender's secret UDP token in its header. Combined with the new NAT rebind, a channel member behind the same public IP (CGNAT, office NAT, shared VPN exit) could rebind — hijack or black-hole — another member's voice. The server zeroes the token before forwarding
- **Server hardening:** TLS handshake timeout (idle TCP sockets could hold all 256 connection slots forever); a malformed frame length now disconnects instead of growing the read buffer without bound; control-message sends are non-blocking so one client that stops reading can no longer stall broadcasts (and, through DashMap shard locks, the whole server); a failed `Authenticated` write no longer leaks the reserved username/session; pre-key bundle requests are rate-limited (one user could drain anyone's one-time pre-keys in seconds); pokes share the chat rate limit; keyframe requests are capped at ~1/s per viewer and only honoured from actual viewers of that share (previously a viewer could force ~50 IDRs/s onto a sharer); a kicked user's screen-share state is torn down like on leave (a kicked viewer kept receiving video)
- **Client:** a client-forged UDP Pong is no longer relayed as voice (it spoofed RTT/keepalive on every receiver); peer text is escaped before it reaches OS notification bodies (freedesktop daemons render markup)

### Fixed
- A rejected channel join (wrong password, channel full) no longer drops the current channel's media key and channel state — the switch is applied only once the server confirms it. Previously voice went silent until the next successful channel change
- Tray *Toggle Mute* / *Toggle Deafen* did nothing (event names didn't match the listeners)
- Voice-activation / always-on mode did not restart the microphone after a reconnect
- Releasing the PTT key while focus was in the chat box left the microphone open
- Switching between sharers could freeze the video until the next keyframe (screen-audio packets updated the sharer tracker without resetting the frame assembler)
- The sticky "UDP blocked" warning survived a successful reconnect
- Global PTT (evdev): unplugging the last keyboard made the listener spin at 100 % CPU and flood the log; PTT is released if it was held at that moment
- Server: the auto-delete timer aborted its own task, sometimes cancelling the `ChannelDeleted` broadcast; unanswered invites of users who disconnected stayed in the invite list forever
- Auto-connect never fired for users who skipped the encrypted chat vault (it waited for an unlock that could not happen)
- Removed dead code: `ts3_bridge.rs` (uncompilable), Signal state persistence (`persistence.rs`, never called), two unused Tauri commands
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
