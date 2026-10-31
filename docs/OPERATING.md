# Running a VoIPC relay

For whoever runs the server. The README's Quick Start gets a relay up; this guide covers
running one for real: installing it, keeping it up, and backing it up and upgrading it
without losing anything.

## 1. Install

Pick one:
- **The static binary**, `voipc-server-linux-x86_64` from a
  [release](https://github.com/luki4fun/voipc/releases/latest). It runs on any x86-64 Linux.
  Verify it first ([SECURITY.md](../SECURITY.md#verifying-a-download)):

      sha256sum -c SHA256SUMS --ignore-missing
      gh attestation verify voipc-server-linux-x86_64 --repo luki4fun/voipc
      install -m 0755 voipc-server-linux-x86_64 /usr/local/bin/voipc-server

- **The container image**, `ghcr.io/luki4fun/voipc-server:<version>`. See section 10.
- **From source:** see [BUILDING.md](../BUILDING.md). The web client must be built first, since
  the server embeds it.

## 2. Where things live

| Path | What |
|---|---|
| `/etc/voipc/server.toml` | the configuration |
| `/var/lib/voipc/` | the working directory: `channels.json`, `server_settings.json`, `bans.json` (relays without accounts), `voipc.db` and its key file (relays with accounts), `files/` (the file cache, §11), `emotes/` (the server's emotes and stickers, §12) |

Paths in `server.toml` that are not absolute are relative to the working directory. Give the
certificate, the key and the database full paths, or start the relay in `/var/lib/voipc`, as
the unit below does.

A relay without accounts writes `bans.json`, the bans that outlast a restart, and the file
cache in `files/`: blobs of files posted in chat, which the clients encrypted before they sent
them (§11). With `[files] enabled = false` it writes nothing else.

## 3. systemd

```ini
# /etc/systemd/system/voipc.service
[Unit]
Description=VoIPC relay
After=network-online.target
Wants=network-online.target

[Service]
User=voipc
Group=voipc
ExecStart=/usr/local/bin/voipc-server --config /etc/voipc/server.toml --cert ${CREDENTIALS_DIRECTORY}/cert.pem --key ${CREDENTIALS_DIRECTORY}/key.pem
LoadCredential=cert.pem:/etc/letsencrypt/live/voice.example.org/fullchain.pem
LoadCredential=key.pem:/etc/letsencrypt/live/voice.example.org/privkey.pem
StateDirectory=voipc
WorkingDirectory=/var/lib/voipc
UMask=0077
Restart=on-failure
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

    useradd --system --home /var/lib/voipc --shell /usr/sbin/nologin voipc
    systemctl daemon-reload && systemctl enable --now voipc
    systemd-analyze security voipc      # 1.5 "OK" for this unit

- **A fixed `voipc` user, not `DynamicUser`.** The admin commands run as a second process on the
  same database. Run them as that user:

      sudo -u voipc voipc-server --config /etc/voipc/server.toml admin grant <name> admin

  Run as root, they would leave root-owned `-wal`/`-shm` files that the service then cannot
  open.
- **Certificates:** `LoadCredential` hands the relay its Let's Encrypt certificate and key
  without opening `/etc/letsencrypt` to it.
- **Stopping:** the relay stops cleanly on SIGTERM, which is what `systemctl stop` sends.

## 4. TLS

- The certificate and key are read once, at start; there is no reload. A certbot deploy hook
  therefore restarts the service (`systemctl restart voipc`). That drops calls in progress, so
  schedule the renewal for a quiet hour.
- With a self-signed certificate, apps trust it the first time they see it. Tell your users
  its fingerprint, so they can compare it with the one the app shows at first contact:

      voipc-server --config /etc/voipc/server.toml cert fingerprint

  The relay also logs the fingerprint at start.

## 5. Network

- Open TCP **and** UDP on the port (9987 by default). TCP serves the page, the file transfers
  (`/f/`, §11) and the fallback; UDP carries QUIC.
- **If UDP is blocked** in front of the server, the page loads but nobody connects.
  `sudo tools/udp-diag.sh` shows where the packets are dropped. If you cannot open UDP, set
  `tcp_fallback = true`; clients then carry everything over the TCP port. Keep `tcp_port` equal
  to `udp_port`.
- IPv6 and hosts with several addresses: see the notes under the config sample in the README.

## 6. Accounts

- **The key file** (`key_file`, or `VOIPC_ACCOUNTS_KEY`) seals the two-factor secrets and keys
  everything the relay hashes. Without it the database is of no use: back the two up together.
- **Postgres:** use `sslmode=verify-full` in the URL when the database is on another host.
- **Commands:**
  - `admin grant|revoke <name> admin|moderator`;
  - `admin reset-2fa <name>`;
  - `admin invite`;
  - `ban list|add|remove`.
  - [ACCOUNTS.md](ACCOUNTS.md) has the details.

## 7. Backups

- **SQLite:** copy the database while the relay runs, readable by the owner only, and keep the
  key file with the copy:

      sudo -u voipc voipc-server --config /etc/voipc/server.toml db backup /var/backups/voipc/voipc-$(date +%F).db

- **Postgres:** use `pg_dump`.
- **Also back up** `server.toml`, `channels.json`, `server_settings.json` and `bans.json`.
- **How long to keep backups: 30 days at most.** A person who deletes their account or their
  kept messages expects them gone. A backup brings them back until it is itself deleted.
- **Restore:** stop the service, copy the files back, start it again. Test a restore once,
  before you need one.

A daily timer:

```ini
# /etc/systemd/system/voipc-backup.service
[Service]
Type=oneshot
User=voipc
ExecStart=/bin/sh -c 'voipc-server --config /etc/voipc/server.toml db backup /var/backups/voipc/voipc-$(date +%%F).db && find /var/backups/voipc -name "voipc-*.db" -mtime +30 -delete'

# /etc/systemd/system/voipc-backup.timer
[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Create `/var/backups/voipc`, owned by `voipc` with mode 0700, and copy the key file there once.

## 8. Upgrading

1. **Read the release notes' first line.** If the protocol changed, every client has to update
   too. The apps say so when they connect.
2. **Verify the download** (section 1).
3. **Back up** (section 7).
4. **Stop, replace the binary, start.** Database migrations run at start.

**When the protocol changes** (the first line says "Protocol N"), an app and a relay connect only
if both speak N. No order keeps everyone connected, but this one strands the fewest:
1. **Tell your users first,** while they can still connect: the day, and to update their apps
   only after the relay. The desktop app offers a new version as soon as it is published, and
   once installed it cannot connect until the relay has moved too. The browser needs nothing;
   Android and the `.deb` are installed by hand.
2. **Update the relay** to the published release, not to a release candidate. A desktop app it
   then refuses finds the matching version in its update feed and offers it; a release
   candidate is never in that feed. The browser gets the new page from the relay itself.
3. **Then the apps.** An app updated before its relay cannot connect to it, and a desktop app
   does not go back by itself (the way back: [COMPATIBILITY.md](COMPATIBILITY.md) §4).

**From 1.0 to 1.3** (protocol 12 to 13):
- **The file cache is on by default** (§11). The relay makes `files/` in its working directory,
  and offers TLS ALPN `http/1.1` with or without `tcp_fallback`, since the apps fetch files over
  the TCP port. If it cannot make the directory, it starts without files and logs why. `[files]
  enabled = false` turns the cache off, but a 1.0 relay refuses that table (below).
- **No migration:** 1.3 adds none to 1.0's, and `channels.json`, `bans.json` and
  `server_settings.json` keep their format.
- **The container:** pin `:1.0` to stay on protocol 12 until your users have updated (§10).

**Going back from 1.3 to 1.0** (checked with the released 1.0.0 binary):
1. Stop the relay.
2. Put the 1.0.0 binary back, or run the `:1.0` image.
3. Delete the `[files]` table from `server.toml`, if you added one: 1.0 refuses to start with it
   (``unknown field `files` ``).
4. Delete `files/`: 1.0 neither uses nor wipes it, so its blobs would stay on disk for good.
5. Start. No database restore is needed, since 1.3 migrated nothing. On a 1.0 relay a password
   reset is checked the 1.0 way again: the reset key that 1.3 accounts carry is not looked at.

The apps go back by hand too ([COMPATIBILITY.md](COMPATIBILITY.md) §4).

**A later release that migrates the database** needs the old binary **and** the backup taken
before the upgrade for a rollback: an older relay refuses a database that a newer one has
migrated, by design. Release candidates (`-rc.N`) are for testing on a relay you can roll back.

[COMPATIBILITY.md](COMPATIBILITY.md) lists what every 1.x keeps working.

## 9. Logs and privacy

- **What is logged:** at the default `info` level, the relay logs no client addresses and no
  account names; connection lines are at `debug`. Set `RUST_LOG=warn` to keep even less.
- **The journal:** it keeps what the service prints. Set its retention to match the backup
  policy, e.g. `MaxRetentionSec=30day` in `journald.conf`.

## 10. Monitoring and the container

`voipc-server --config … health` exits 0 when the relay answers on its TCP port, and 1 when it
does not. Use it from a monitoring check. The container image uses it as its HEALTHCHECK.

The container image is static and runs as the non-root user 65532. Its working directory and
volume is `/data`. `/data` holds `server.toml`, the certificate and the key, with paths
relative to `/data`, and what the relay writes there. The image has no shell, so put the three
files in from outside before the first start. Until they are there, the relay exits at once
with `failed to read config file`.

The simplest way is a host directory that user 65532 owns:

    install -d -o 65532 -g 65532 -m 0700 /srv/voipc
    install -o 65532 -g 65532 -m 0600 server.toml cert.pem key.pem /srv/voipc/
    docker run -d --name voipc -v /srv/voipc:/data \
      -p 9987:9987/tcp -p 9987:9987/udp ghcr.io/luki4fun/voipc-server:1.5.0
    docker exec voipc /voipc-server --config /data/server.toml admin grant <name> admin

With a named volume instead, copy the files in with a throwaway container first, then run the
relay with `-v voipc:/data`:

    docker run --rm -v voipc:/data -v "$PWD":/src:ro busybox \
      sh -c 'cp /src/server.toml /src/cert.pem /src/key.pem /data/ && chown -R 65532:65532 /data'

A release candidate only gets its own `:<version>` tag. A final release also moves
`:<major>.<minor>`, `:<major>` and `:latest`: 1.3.1 moves `:1.3`, `:1` and `:latest`, and
`:1.0` stays where 1.0 left it.

`:1` and `:latest` follow protocol changes too. A relay that pulls either of them by itself
(Watchtower and the like) moves to protocol 13 on the day 1.3.1 is published, and every 1.0 app
on it is refused from then on. To keep 1.0 apps connecting, pin `:1.0` until your users have
updated, then move to `:1.3` (§8).

## 11. The file cache

Files posted in chat are encrypted by the sender's app, each under its own key, which travels
only inside the end-to-end encrypted message. The relay keeps the encrypted blob for a while, so
that members can load it later. It never downloads anything by itself: a member clicks Load.
The bytes go over HTTPS on `tcp_port`, never over the QUIC connection that carries voice.

```toml
[files]
enabled = true             # false: no cache, and the apps hide the attach button
max_size_mb = 10           # largest blob: the file, deflated where that helps, plus 32 bytes and 16 per 64 KiB; at most 65
cache_mins = 30            # a blob nobody fetched for this long is deleted
max_age_hours = 24         # and every blob this long after it arrived, however often it is fetched
max_total_mb = 1024        # all blobs together; when full, the least recently used goes
upload_mb_per_hour = 200   # per connection and per address (an IPv6 /64)
download_mb_per_hour = 2000
dir = "files"              # relative to the working directory: /data/files in the container
animation_side = 1024      # a moving picture posted here is drawn at most this many pixels a side (256 to 2560)
animation_mb = 128         # and its frames take at most this many MiB in each app (16 to 512)
```

- **Moving pictures (1.4).** Every member's app draws a GIF, APNG or animated WebP from the chat
  itself, and keeps all its frames in memory while it is on screen. `animation_side` and
  `animation_mb` say how much: a longer or larger one keeps every other frame, so it plays
  choppier but as long, and is never refused for that. The relay tells the apps, which hold both
  to the ranges above whatever a relay says. A still picture is always drawn up to 2560 pixels a
  side.

- **Wiped at every start.** Only the blob files in `dir` are deleted: their names are 64 hex
  digits, or that and `.<n>.part` (an upload under way, or a blob on its way out). A file that
  cannot be deleted is logged, and the rest still go. Nothing else in the directory is touched,
  but give it a directory of its own anyway.
- **Private to the relay's user.** The relay makes `dir` with mode 0700, and narrows an existing
  one to that (with a warning if it cannot); each blob is written with mode 0600. The names are
  the blobs' hashes, and the sizes show.
- **When a blob has gone**, a member's Load asks the other members of that conversation who are
  online, and of no other conversation the file was posted in. This includes a file posted before
  the relay last restarted, whose record went with the restart. An app that has the file, and a message in that conversation that refers to it,
  uploads it again without showing anything. After 60 seconds without one, the member sees
  that nobody online has the file. A conversation is asked at most once a minute for one file.
- **Who may fetch.** Only members of a conversation the blob was posted in: a channel's current
  members, or the two people of a direct conversation, by account or else by the guest's
  connection (a guest who comes back, or another who takes the name, is someone new). A member who
  asks for a file their conversation never had is answered like one whose file has gone (their
  conversation is asked, and nobody there has it). Everyone else is refused.
- **What the relay learns:** each blob's exact size (blobs are not padded, so a size can hint
  at what kind of file it is), when it is uploaded and fetched and by which connection, and
  which conversations it was posted or forwarded in, which links them. A re-upload also shows
  which members still hold it. Not its name or its contents.
  [THREAT-MODEL.md](THREAT-MODEL.md) has the rest.
- **Disk:** at most `max_total_mb`, uploads in progress included. A cached blob is evicted
  only for bytes that arrive, never for an upload that has not sent any.
- **Ports:** the desktop and Android apps fetch files from the port they connect to, over TCP,
  as the fallback does. Keep `tcp_port` equal to `udp_port` (the default); the relay warns at
  start when they differ.
- **Off:** `enabled = false` leaves `dir` alone except that blob files from an earlier run are
  still wiped at start.
- **Whoever holds a file's id** (only its messages carry it) can file it under a conversation of
  their own and fetch the blob. That reveals nothing without the key, which only the messages
  carry, but it means the relay's check keeps out people who never had the message, not people
  who did.

## 12. Emotes and stickers

Since 1.4, a server's admins add emotes and stickers in the app (the admin panel's Emotes tab):
pictures, a folder, a `.zip` or a WhatsApp `.wastickers`, or in the desktop app a Discord
server's, a 7TV set or a Twitch channel's BetterTTV emotes. Members use them as `:name:`;
stickers, off until an admin turns them on there, go as messages of their own.

```toml
[emotes]
enabled = true             # false: no emotes, and the apps show none
max_emote_kb = 256         # the largest emote file an admin may add (1 to 1024)
max_sticker_kb = 512       # and sticker file (1 to 1024)
max_total_mb = 32          # all of them together, held in memory (1 to 1024)
dir = "emotes"             # kept across restarts; never [files] dir, nor inside or around it
```

- **Kept, and readable.** Unlike the file cache, emotes are the server's own, like its channel
  names: the relay keeps each file as it came, under its hash, in `dir` (with `manifest.json`,
  the list), across restarts, and serves it to members. The list does not say who added what.
- **The relay never decodes them.** It checks each file's hash, its size and its first bytes (a
  PNG, GIF, WebP or JPEG) and nothing more. Every member's app decodes the file itself, with
  memory-safe code under fixed limits, and shows only a PNG it wrote: whatever an admin or a
  relay sent, no picture reaches the app's or the browser's own decoder.
- **What the relay learns:** nothing about who uses which. Every member's app fetches every
  emote when the list comes, and `:name:` travels inside the end-to-end encrypted messages.
- **Who may change them:** admins only (the token, or an account with the admin role).
- **Memory and bandwidth:** all of `max_total_mb` is held in memory, and every member downloads
  each emote once (the apps keep their copy). Since 1.5 a connection may download twice
  `max_total_mb` (plus one sticker) at once, and `max_total_mb` an hour after that; past it, the
  relay answers 429, so one member fetching in a loop cannot fill the uplink voice needs.
- **Changes are written once a second at most:** an import of hundreds, or removing a pack, is
  one write of `manifest.json` and one new list for members. A new file is on disk before its
  upload is answered, and a stopping relay writes the manifest before it exits.
- **At start**, an entry whose file is missing or is not the file its hash names is dropped, and a
  file no entry names is deleted. Nothing else in `dir` is touched.

