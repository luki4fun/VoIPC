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
| `/var/lib/voipc/` | the working directory: `channels.json`, `server_settings.json`, `bans.json` (relays without accounts), `voipc.db` and its key file (relays with accounts), `files/` (the file cache, §11) |

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

**From 1.2 to 1.3:** the file cache is on by default (§11). The relay makes `files/` in its
working directory and offers TLS ALPN `http/1.1` with or without `tcp_fallback`. To keep a 1.3
relay writing what 1.2 wrote, set `[files] enabled = false`. If it cannot make the directory, it
starts without files and logs why.

A rollback needs the old binary **and** the backup taken before the upgrade: an older relay
refuses a database that a newer one has migrated, by design. Release candidates
(`-rc.N`) are for testing on a relay you can roll back.

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
      -p 9987:9987/tcp -p 9987:9987/udp ghcr.io/luki4fun/voipc-server:1.1.0
    docker exec voipc /voipc-server --config /data/server.toml admin grant <name> admin

With a named volume instead, copy the files in with a throwaway container first, then run the
relay with `-v voipc:/data`:

    docker run --rm -v voipc:/data -v "$PWD":/src:ro busybox \
      sh -c 'cp /src/server.toml /src/cert.pem /src/key.pem /data/ && chown -R 65532:65532 /data'

A release candidate only gets its own `:<version>` tag. A final release also moves `:1.0`, `:1`
and `:latest`.

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
```

- **Wiped at every start.** Only the blob files in `dir` are deleted: their names are 64 hex
  digits, or that and `.<n>.part` while an upload runs. Nothing else in the directory is
  touched, but give it a directory of its own anyway.
- **When a blob has gone**, a member's Load asks the other members of that conversation who are
  online. An app that has the file, and a message in that conversation that refers to it,
  uploads it again without showing anything. After 60 seconds without one, the member sees
  that nobody online has the file.
- **Who may fetch.** Only members of a conversation the blob was posted in: a channel's current
  members, or the two people of a direct conversation, by account or else by name. Everyone
  else gets the same refusal as for a blob that does not exist.
- **What the relay learns:** each blob's size, when it is uploaded and fetched and by which
  connection, and which conversations it was posted or forwarded in, which links them. A
  re-upload also shows which members still hold it. Not its name, type or contents.
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

