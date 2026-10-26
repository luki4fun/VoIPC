# Compatibility

From 1.0, VoIPC keeps the contracts below for every 1.x release. A change that breaks one
waits for 2.0. The one exception, by design, is the wire protocol: client and relay must speak
the same protocol version, a 1.x release may bump it, and its release notes say so in their
first line.

Each contract names the test that catches a break. A contract without a test is a promise
nobody checks, so a new one comes with its test.

## 1. Wire protocol (client ↔ relay)

**1.x keeps:**
- A relay admits a client exactly when their `PROTOCOL_VERSION` is equal (12 in 1.0). The app
  version is informational only.
- A refused client is told why:
  - a client at protocol 12 or later gets `ServerMessage::Refused { code, server_protocol,
    server_version, text }`, with `code` 1 (`REFUSED_VERSION`) for a protocol mismatch. The app
    shows "update to X" or "this server is older" from it, and the desktop updater looks for a
    matching version;
  - a client at protocol 11 or older (0.12 and before) gets the free-text `AuthError`
    containing "version mismatch", which those versions already show.
- These bytes are frozen for good, so that any version can tell any other one to update:
  - the start of `Authenticate` (`username`, `protocol_version`);
  - `AuthError`;
  - `Refused`, its variant index and its `u16` code.

**May change:** any other layout, but only together with a protocol bump, and only in a minor or
major release, never in a patch. The release notes name the oldest relay and app that speak
it. A patch release never bumps the protocol, because auto-updates would otherwise lock users
out of servers that have not upgraded yet.

**Break detection:** `crates/voipc-protocol/tests/golden.rs`.
- It compares the traced format of every message and every type inside one against
  `golden/v<N>.json`, and the frozen messages and the media packet headers against bytes
  written out in the test.
- Any change with the same `PROTOCOL_VERSION` fails it.

## 2. Game SDK (`docs/SDK.md`)

**1.x keeps:**
- `hello.sdk = 1`, with every 1.0 message type and field, their meanings and their defaults;
- every error `code` in SDK.md's table. Mods match on `code`; `reason` is English and may change;
- `POST /game/v1/routes`: the request and response shape, the 404 while `game_token` is unset,
  and the loopback-only socket.

**May change:**
- new optional fields;
- new message types from the app to the mod: mods ignore a `type` they do not know;
- new message types from the mod to the app: an older app answers them with `unknown_type`,
  which is not counted toward closing the socket;
- tighter checks on which origins may connect, as a security fix.
- A breaking change is `sdk: 2`. The app keeps answering `sdk: 1` mods for all of 1.x.

**Break detection:** `crates/voipc-audio/src/game.rs` and its tests (the pure SDK parsing), the
`game` fuzz target, and `sdk/test-mod.mjs` against a running app.

## 3. Server configuration

`server.toml`, `channels.json`, `server_settings.json`, `bans.json`, the command line and
the environment (`VOIPC_ADMIN_TOKEN`, `VOIPC_ACCOUNTS_KEY`, `RUST_LOG`).

**1.x keeps:** every 1.0 key, flag, subcommand and environment variable, with its meaning and
its default. Relative paths resolve from the working directory, as before.

**May change:**
- new optional keys, with defaults that keep the old behaviour;
- a deprecation, with a warning at start; removing or renaming waits for 2.0;
- stricter validation only where the old value was unsafe, with a clear refusal to start.

**What changed from 0.12 to 1.0** (the last breaks before the contract):
- **Admin and game tokens:** 1.0 refuses to start with an admin or game token shorter than 16
  characters. The sample `admin_token = "change-me"` from 0.12's README is one of those.
- **Unknown keys:** the top level of `server.toml` is strict. An unknown key stops the start
  with an error naming the key, where 0.12 ignored it; `[accounts]` was strict already.
  `web_port`, gone since 0.5, is still accepted.

**An older relay on a newer config:** it refuses the unknown key, never ignores it, so a relay
cannot silently run without a setting it was given. The JSON files stay lenient: a rewrite of
`channels.json` keeps keys it does not know.

**Break detection:** `crates/voipc-server/src/upgrade_fixtures.rs`. Every preset's
`channels.json` and `server_settings.json` written by 0.12.0, and 0.12.0's documented
`server.toml`, must still load, and the channel passwords 0.12.0 hashed must still open.

## 4. Persisted data

Covered: the desktop chat history, vault items, TOFU pins, `settings.json`, the browser's
storage, the accounts database, the kept-message log and its crypto labels.

**1.x keeps:**
- Every 1.x opens everything any earlier 1.x, and 0.12, wrote.
- An upgrade moves data forward and never loses any. The desktop history keeps a one-time
  copy of the older file, named after its format, the first time a newer version opens it:
  `chat_history.bin.v4` when 1.0 opens a 0.12 file, `chat_history.bin.v5` when 1.2 opens a
  1.0 or 1.1 one.
- Shipped database migrations are append-only and never edited.
- The crypto labels are frozen: `voipc-vault-item/v1|`, `voipc-log/v1|`, `voipc-wrap/v1|`,
  `voipc-channel/v1|`, the HKDF infos and the AADs. A new scheme gets a new label beside the
  old one, and the old one stays readable.

**An older build on newer data** refuses it and never writes over it:

| Data | Newer than this build |
|---|---|
| desktop chat history | "written by a newer VoIPC"; the file is not touched, and "create" refuses to replace it |
| `settings.json` | read, never saved over (`format` above this build's) |
| TOFU pins | an unreadable file is kept, and self-signed servers are refused until it is reset |
| vault items | read-only for the session, with a warning (item `0x02` + `gen`) |
| browser IndexedDB | refused by its version check |
| accounts database | sqlx refuses a database with migrations it does not know |

A downgrade is not supported, but it is safe: nothing is destroyed.

**Break detection:**
- the fixtures written by 0.12.0's own code, one directory per released version, never
  regenerated:
  - `crates/voipc-crypto/tests/fixtures/0.12.0/`: vault, log key, kept entry, safety number, log
    memory;
  - `client/src-tauri/tests/fixtures/0.12.0/`: chat history, settings, pins;
  - `client/src-tauri/tests/fixtures/1.1.0/`: chat history (archive v5, the format 1.0 and 1.1
    write);
  - `crates/voipc-server/tests/fixtures/0.12.0/`: the accounts database, which is opened,
    migrated and signed into, and the kept DM read;
  - `client/src/lib/__fixtures__/0.12.0/`: browser settings, checked by `test-ui.mjs`
    section 18;
- `crates/voipc-server/tests/migrations.rs`: a shipped migration's hash may not change;
- a "newer than me" test per format.

Each release adds its own fixture directories (a release-checklist step).

## 5. Security claims

**1.x keeps:** the claims in README → Security, `docs/ACCOUNTS.md` and `docs/THREAT-MODEL.md`.

**May change:** a claim may get stronger. Weakening one needs a published GitHub security
advisory and a "Security" entry in the CHANGELOG. It never happens silently.

**Break detection:**
- every row of `docs/THREAT-MODEL.md` names the code and tests that hold it;
- before each release, every row whose files changed since the last tag is read again:
  `git diff --stat <last-tag> -- <files>`.

## 6. Release files

**1.x keeps:**
- **Assets:** the release asset names (`voipc-server-linux-x86_64`, `VoIPC_<v>_amd64.AppImage`,
  `VoIPC_<v>_amd64.deb`, `VoIPC_<v>_x64-setup.exe`, `VoIPC-android-<v>.apk`,
  `VoIPC-web-<v>.tar.gz`), the updater's `latest.json`, `VoIPC_<v>_amd64.AppImage.sig` and
  `VoIPC_<v>_x64-setup.exe.sig`, plus `SHA256SUMS` and a build attestation for every file.
  `latest.json` is the name every 1.x client's stable feed URL ends in.
- **Container:** the image `ghcr.io/luki4fun/voipc-server` with `:<version>`; a final release
  also moves `:<major>.<minor>`, `:<major>` and `:latest`.
- **Updater feeds:** stable is `releases/latest/download/latest.json`; release candidates read
  `releases/download/updater-rc/latest.json`.
- **Release candidates:** `v<x.y.z>-rc.<n>` releases are pre-releases. They never become
  "latest", and they ship no `.deb`, because dpkg would sort the final release below them.
