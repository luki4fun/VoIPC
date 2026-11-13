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

- **The relay ends TLS itself, for QUIC and for the TCP fallback.** Since 1.12 an app binds its
  sign-in to its own TLS session, and the relay checks that against its end. Port forwarding and
  proxies that pass TLS through are fine; one that ends TLS in front of the TCP port breaks app
  sign-ins over the fallback (guests and browsers are unaffected).
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
- IPv6 and hosts with several addresses: see the notes under the config sample in §13.

## 6. Accounts

- **The key file** (`key_file`, or `VOIPC_ACCOUNTS_KEY`) seals the two-factor secrets and keys
  everything the relay hashes. Without it the database is of no use: back the two up together.
- **Postgres:** use `sslmode=verify-full` in the URL when the database is on another host.
- **Commands:**
  - `admin grant|revoke <name> <group>` (`admin`, `moderator`, or one made in the app);
  - `admin reset-2fa <name>`;
  - `admin reclaim <name>` (no password, every device and the recovery key lost);
  - `admin invite`;
  - `ban list|add|remove`.
  - [ACCOUNTS.md](ACCOUNTS.md) has the details.
- **Sign-in with a provider** (`public_url`, `VOIPC_OAUTH_<PROVIDER>_ID` and `_SECRET`) needs a public
  certificate on this port. Apps that pinned the old self-signed one accept it, since the public CAs do, and
  go on doing so at each renewal. `signups_per_hour` (60) bounds new accounts: raise it for a move if you
  expect newcomers. An account the move made is not one. Starting a sign-in is limited per address, per IPv6 /48 and
  per /32. If the log says 4096 are open at once, someone is filling the table: the relay drops from whoever holds the
  most and refuses nobody, and password sign-in is unaffected.
- **Moving a Discord server here** ([MOVING.md](MOVING.md)) needs `*`, a code and `cloud = true`, and the desktop app
  for the import itself. An account the move made and nobody opened goes after `unclaimed_days` (90; 0 is never), counted
  from the first import, and frees its name. Importing writes in small transactions, so a long run holds up nobody; each
  member who comes takes one short lock, which a move post can queue up for a moment.
- **Mutes and timeouts** live in the database (`voipc_restrictions`), so they outlast a restart: an account's by its id, a guest's as a keyed hash of the address, never the address. A row goes when it is lifted or runs out, and with its account. On a relay without accounts they live in memory, so a reconnect keeps them and a restart does not. No shell command touches them.
- **Hiding messages** keeps nothing new here of itself: a hide travels end to end like a message, and goes where the
  channel's stored messages go. The moderator's app also adds a row to the moderation log, naming who hid or restored
  whose message in which channel, with the message's id. Every client is told each account holding a privilege, from your groups, at connect and when it
  changes. What your shell changes reaches them within five minutes.
- **The moderation log** (*Server admin*, for holders of `voipc:modlog`) lives in the database. `modlog_days`
  (180) is how long a row and the names in it stay, by time alone; 0 stops the start. Whoever holds the database can
  change it, so back it up and guard it as the record it is.
- **What came from Discord** stays until someone removes it. `archive_days` (0, never) takes rows older than that many
  days by when they were written, which cannot be undone, so it is a choice to make and tell your members. A worker
  deletes in batches of 5,000 with a pause between, so a large removal does not hold up sign-ins. Readers stop getting
  what someone deleted at once; rows past `archive_days` go when the worker reaches them, within the hour on a small
  archive.
- **Removing a banned member's posts** deletes rows of `voipc_log` for good: back them up if you may want them. It
  keeps the direct messages and every key, so someone back from a ban reads and writes as before. Everyone who connects
  is told of each removal still in the moderation log, the newest 2,000, so `modlog_days` is also how long a device
  coming back hears of one. Files stay until `max_age_hours` takes them. From the shell, ban first; the removal itself
  is made in the app, from *Active bans*.
- **Reports** keep no row of their own: a report is a direct message to each holder of `voipc:reports`, and the relay
  only answers who they are. A report that carries the message's file, the default until it is unticked, lists that
  file under the direct message too, as any forward does, so the relay can see which conversation it came from.
  There is no setting beyond who holds it, and nothing to back up. Reports reach someone away
  through the stored log, so with `cloud = false` they reach only those online. Admins hold it anyway, and on a relay
  without accounts so does whoever logged in with the token, while connected. Give the privilege to someone who reads
  their messages: where nobody who holds it can be reached, the dialog says nobody takes reports.
- **In the app** (*Server admin*): channels and categories, the server's name and icon, invite links.

## 7. Backups

- **SQLite:** copy the database while the relay runs, readable by the owner only, and keep the
  key file with the copy:

      sudo -u voipc voipc-server --config /etc/voipc/server.toml db backup /var/backups/voipc/voipc-$(date +%F).db

- **Postgres:** `pg_dump -Fc`, as the unit below runs it. A dump holds no index and no dead rows.
- **Also back up** `server.toml`, `channels.json`, `server_settings.json`, `bans.json` and
  `emotes/`. After a move from Discord the database records each emote as brought, so a later
  run skips it: a database restored without its `emotes/` keeps the move's emotes away for
  good, and posts show their names as plain words.
- **How long to keep backups: 30 days at most.** A person who deletes their account or their
  kept messages expects them gone. A backup brings them back until it is itself deleted.
- **A run from Discord** copies a SQLite database first, beside it, as `<database>.before-import-<run>`,
  readable by the owner only. A run resumed after its copy was dropped gets a new one, `<database>.before-resuming-import-<run>`,
  which holds what the run had done before it stopped. A new run drops all but the last two, and nothing in the relay removes them otherwise: they
  stay until you delete them. Postgres has nothing to make one from here: `pg_dump` first, and tick that you did. These
  hold everything, so the 30 days apply to them too: delete them when you know the move went well. The daily timer below
  does it at 30 days if you have not.
- **A self-update's copy** of a SQLite database (§14) is one plain copy beside the binary. The newest two stay, and at each
  update one past 30 days goes too, though never the newest: if no update comes, the timer below takes that one at 30 days.
- **Kept channel messages and their keys are in every copy too,** and nothing compresses them much, since they are encrypted.
  Measured per row at 2000 members, 300 channels and 1,500 writers-in-channels:

  | Row | SQLite | Postgres |
  |---|---|---|
  | A kept message of about 100 characters | 409 B | 480 B |
  | A member's key to a writer in a channel | 114 B | 216 B |
  | A writer's new key, for about 60 members at once | 91 B | 161 B |

  With the default `kept_window` of 10,000, on such a server, that comes to about 4 GB on SQLite and 7 GB on Postgres at 173,000 messages a
  day, and about 6 GB and 11 GB at 46,800 a day, where quieter channels keep more keys for longer. With the 7 copies below, about 25 to 45 GB
  in all. Those totals are sums from the rows above, not a year's run. A smaller `kept_window` is the way to spend less. Deduplicating backup
  tools save next to nothing on these files: nearly every byte differs from one day's copy to the next.
- **What came from Discord is in every copy,** and the daily timer below keeps 7 of them:

  | Messages | SQLite | Postgres | One SQLite copy, plain / zstd | 7 plain copies, a sum |
  |---|---|---|---|---|
  | 1 M | 0.18 GB | 0.26 GB | 0.17 / 0.07 GB | 1.2 GB |
  | 5 M | 0.85 GB | 1.24 GB | 0.84 / 0.32 GB | 5.9 GB |
  | 20 M | 3.5 GB | 5 GB | 3.4 / 1.3 GB | 24 GB |
  | 100 M | 18 GB | 26 GB | 17 / 6.5 GB | 119 GB |

  The relay has no free-disk check, and when the disk is full sign-ins fail too.
  A copy made before someone's deletion still holds their posts until it is deleted, which the timer below does within
  30 days. Put the database and its copies on an encrypted disk ([MOVING.md](MOVING.md#data-protection)).
- **Restore:** stop the service, `gunzip` the copy first and copy the files back (Postgres: `pg_restore --clean --if-exists
  -d voipc` from the dump), start it again. Test a restore once, before you need one.
- **A restore puts back whoever left or was removed since the copy.** Their seat returns with the rest, and writers' apps
  hand them keys again at their next post, each named as it happens, until someone removes them again.
- **A restore also takes back what members deleted since.** It is there again, and on a server that moved from Discord
  their wishes are gone too, so the next run files those posts again. To start a move over, use Undo instead
  ([MOVING.md](MOVING.md#undo-and-re-runs), which says what to do if you have to restore).

A daily timer, which keeps 7: today, the two days before and the last four Sundays, the oldest 27 days old. `%u` names a
Sunday 7, and `-f` lets a second run on one day replace the copy instead of stopping the job there:

```ini
# /etc/systemd/system/voipc-backup.service
[Service]
Type=oneshot
User=voipc
ExecStart=/bin/sh -c 'f=/var/backups/voipc/voipc-$$(date +%%F-%%u).db && voipc-server --config /etc/voipc/server.toml db backup "$$f" && gzip -qf "$$f" && find /var/backups/voipc -name "voipc-*.db.gz" \\( -mtime +27 -o \\( -mtime +2 ! -name "*-7.db.gz" \\) \\) -delete && find /var/lib/voipc -maxdepth 2 -name "voipc*before-*" -mtime +30 -delete'

# /etc/systemd/system/voipc-backup.timer
[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

On Postgres the same timer with this service. A custom-format dump is compressed already:

```ini
# /etc/systemd/system/voipc-backup.service
[Service]
Type=oneshot
User=voipc
UMask=0077
ExecStart=/bin/sh -c 'pg_dump -Fc -d voipc -f /var/backups/voipc/voipc-$$(date +%%F-%%u).dump && find /var/backups/voipc -name "voipc-*.dump" \\( -mtime +27 -o \\( -mtime +2 ! -name "*-7.dump" \\) \\) -delete'
```

Create `/var/backups/voipc`, owned by `voipc` with mode 0700, and copy the key file there once. The SQLite unit's last
`find` is for the copies a run from Discord and a self-update leave beside the database and the binary. Change its path
and name if yours differ.

## 8. Upgrading

1. **Read the release notes' first line.** If the protocol changed, every client has to update
   too. The apps say so when they connect.
2. **Verify the download** (section 1).
3. **Back up** (section 7).
4. **Stop, replace the binary, start.** Database migrations run at start.

**When the protocol changes** (the first line says "Protocol N"), the relay admits only apps
that speak N. Since 1.6 an app also talks to relays up to three protocols older, so the apps go
first:
1. **Tell your users to update their apps.** A 1.6 or later app keeps talking to your relay
   meanwhile, with a banner saying what is off until it updates. The browser needs nothing;
   Android and the `.deb` are installed by hand.
2. **Then update the relay** to the published release, not to a release candidate (unless it
   updates itself with `release_candidates = true`, §14). An app it then refuses for being
   older finds the matching version in its update feed and offers it; a release candidate is
   never in that feed. The browser gets the new page from the relay itself.

Apps before 1.6 talk only to a relay of their own protocol: for those, update the relay first
and the apps right after (the way back: [COMPATIBILITY.md](COMPATIBILITY.md) §4).

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

**From 1.6 to 1.11** (protocol 15 to 21), the step most relays take, since 1.7 to 1.10 were
release candidates only. The notes below for 1.9 to 1.10 and 1.10 to 1.11 hold for it too; on top
of them:
- **Apps first:** a 1.11 app talks to the 1.6 relay meanwhile, with a banner saying what is off;
  a 1.6 app cannot talk to a 1.11 relay.
- **Three more migrations:** `0005_gates.sql` (who may see and join a channel, and speak in it),
  `0006_community.sql` (channels made in the app, and where each channel sits) and
  `0007_group_sections.sql`. Going back takes the 1.6 binary and the backup.
- **New keys, with defaults that change nothing:** `public_url` (empty: no sign-in with Discord,
  Google or Facebook) and `signups_per_hour` (60) in `[accounts]`, and `server_name` and
  `server_description` in `server_settings.json` (for a relay without accounts). A 1.6 relay
  refuses the first two ([COMPATIBILITY.md](COMPATIBILITY.md)).

**From 1.9 to 1.10** (protocol 18 to 19):
- **A migration:** `0008_moderation.sql` adds the moderation log and the restrictions, so going back takes the old binary
  and the backup.
- **The moderator group** gains the four new privileges once, on the first start, if it still holds exactly kick, ban and
  channels, and the log says so. A group you edited is left alone: tick them yourself, or only `*` has the tools.
- **New keys, with defaults that change nothing:** `modlog_days` in `[accounts]` and `new_member_wait_mins` in
  `server_settings.json`.

**From 1.10 to 1.11** (protocol 19 to 21):
- **A migration:** `0009_move.sql` adds what a move from Discord holds, empty until you run one, so going back takes the
  old binary and the backup.
- **A migration:** `0010_kept.sql` adds the tables kept channel messages move to. What a channel kept before stays where it
  is and goes on opening for whoever held its key; a writer who shares hands those keys on as well. Every post from here on is on a chain.
- **New keys, with defaults that change nothing:** `archive_days` (0, kept until removed) and `unclaimed_days` (90) in
  `[accounts]`.
- **New keys that do:** `kept_window` (10,000). A channel with more than that deletes the rest at the next sweep once it has
  stood three days, and `kept_seats` (5000) lifts what was fixed at 256.
- A relay that never moves a server does no new work.

**From 1.11 to 1.12** (protocol 21 to 23; 1.12.0-rc.1 was 22, so its apps and relays update too):
- **Apps first**, as for any protocol: a 1.12 app talks to the 1.11 relay meanwhile.
- **A migration:** `0011_promises.sql` remembers a ban lifted for someone who deleted their own
  account, and the Discord ids an account unlinked, so that deleting it later still takes what the
  move filed under them. Going back takes the old binary and the backup.
- **A second migration (rc.2):** `0012_round_c.sql` builds three indexes on the moved Discord
  archive and one on the old log's direct messages, and adds a table for channel deletions in
  progress. Building an index reads the whole table once, so on a relay holding millions of
  archived or old direct rows the first start takes longer than usual (seconds per million rows
  on SQLite); it is one transaction, and a stop halfway leaves nothing done. Deleting a channel
  with a large kept log now takes its rows a few thousand at a time in the background, and a
  start finishes what a stop left; until then nothing of the channel can be read.
- **The password never leaves an app again.** The first time an account gives its password to a
  1.12 app (a sign-in, or confirming it on a device signed in another way), the app moves it to
  a key derived from it (l4f-accounts 0.14 keeps that key in the password's place); from then on
  that account's password is checked as a signature and its secret opens nothing. An account
  that never gives its password again stays as it was.
- **The relay must end TLS itself** (§4): an app's sign-in is bound to its own TLS session. A
  proxy that passes TLS through is fine; one that ends it in front of the TCP fallback makes
  app sign-ins over that fallback fail.

**A later release that migrates the database** needs the old binary **and** the backup taken
before the upgrade for a rollback: an older relay refuses a database that a newer one has
migrated, by design. Release candidates (`-rc.N`) are for testing on a relay you can roll back.

[COMPATIBILITY.md](COMPATIBILITY.md) lists what every 1.x keeps working.

## 9. Logs and privacy

- **What is logged:** at the default `info` level, the relay logs no client addresses and no
  account names; connection lines are at `debug`. Set `RUST_LOG=warn` to keep even less.
- **The account system's own lines** (target `accounts`): its warnings and errors are on by
  default, among them why a Discord sign-in failed (`outcome="oauth_failed"`) and database
  errors, with a hashed address and account ids. A `RUST_LOG` of your own replaces the default,
  so add `accounts=warn` to it. `accounts=info` adds each sign-in's outcome, and names the first
  admin account when it is made.
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
      -p 9987:9987/tcp -p 9987:9987/udp ghcr.io/luki4fun/voipc-server:1.12.0-rc.2
    docker exec voipc /voipc-server --config /data/server.toml admin grant <name> admin

With a named volume instead, copy the files in with a throwaway container first, then run the
relay with `-v voipc:/data`:

    docker run --rm -v voipc:/data -v "$PWD":/src:ro busybox \
      sh -c 'cp /src/server.toml /src/cert.pem /src/key.pem /data/ && chown -R 65532:65532 /data'

A release candidate only gets its own `:<version>` tag. A final release also moves
`:<major>.<minor>`, `:<major>` and `:latest`: 1.3.1 moves `:1.3`, `:1` and `:latest`, and
`:1.0` stays where 1.0 left it.

`:1` and `:latest` follow protocol changes too. A relay that pulls either of them by itself
(Watchtower and the like) moves to a new protocol on the day a release that changes it is
published, and every app on the old protocol is refused from then on. To keep those apps
connecting, pin `:<major>.<minor>` until your users have updated, then move on (§8). Which
release speaks which protocol: [COMPATIBILITY.md](COMPATIBILITY.md) §1.

`[update]` (§14) refuses to start in the container: its binary is part of the image. Pull a new
tag instead, by hand or with `podman auto-update` and the `io.containers.autoupdate=registry`
label.

## 10a. How big one relay goes

**Give the relay's UDP socket room, on any relay with more than a few dozen people.** Every client's voice, video and
control packets wait in one socket's buffer while the relay is busy, and what does not fit is dropped without a word in any
log. The relay asks for 8 MiB, and Linux gives at most twice `net.core.rmem_max`, which is usually only 212 KiB. It
warns at start if it got less. On the host, a container's included:

```sh
sysctl -w net.core.rmem_max=4194304 net.core.wmem_max=4194304   # and the same in /etc/sysctl.d/ to keep it
```

At 2000 clients on this machine that took the packets dropped from 340,000 to under 11,000 a run, and all of them joining a
channel from about 3 s to about 1 s. `nstat -az UdpRcvbufErrors` counts what the kernel has dropped this way.

Measured with `community_load` (below) on one relay and one 32-thread machine with
62 GiB, load clients on the same machine, 2026-11-04: guests, no voice, N clients arriving at
50 a second, all joining one text channel at once, then one 200-byte chat message a second.

| Clients | Relay's cores | Join all (s) | Join p95 (ms) | Rosters short | Chat p95 (ms) | Chat delivered | Relay RSS (MiB) |
|---|---|---|---|---|---|---|---|
| 500 | all | 0.2 | 77 | 0 | 3 | all | 107 |
| 1000 | all | 1.0 | 239 | 0 | 5 | all | 229 |
| 2000 | all | 3.8 | 1543 | 0 | 9 | all | 523 |
| 500 | 2 | 0.2 | 145 | 0 | 3 | all | 97 |
| 1000 | 2 | 0.8 | 426 | 0 | 8 | all | 198 |
| 2000 | 2 | 3.4 | 1990 | 0 | 12 | all | 532 |

On a relay with accounts (1.9), where each connection also reads the groups' colours, the server's name
and who may call on everybody:

| Clients | Cores | Join, s | Join p95, ms | Short rosters | Chat p95, ms | Delivered | Relay MiB |
|---|---|---|---|---|---|---|---|
| 500 | all | 0.2 | 84 | 0 | 3 | all | 114 |
| 1000 | all | 0.6 | 269 | 0 | 5 | all | 246 |
| 2000 | all | 3.2 | 1595 | 0 | 10 | all | 561 |
| 2000 | 2 | 3.0 | 2022 | 0 | 24 | all | 739 |

Moderation (protocol 19) adds who holds privileges, running restrictions and removal marks to each
connection, with no measurable cost: 2000 clients joined in 2.4 s (2.6 s on 2 cores) with p95 1452 ms
(2342 ms), no short rosters, every message delivered, at 569 MiB (668 MiB).

So the relay itself carries 2000 connections. What a connection may have waiting is bounded at 16 MiB
of messages. Past that its client has stopped reading, and the relay ends the connection (the log says so)
rather than let it fall behind quietly: the app reconnects and gets the whole state again. The limits a
real community meets first are these:

- **One message holds one list.** `UserList` fits 2621 guests, 1598 accounts, or 789 accounts with three
  badges each; `ChannelList` 1213 channels, 555 with a 64-byte description, 210 with 256 bytes. Past that
  the relay sends the rest in further messages and every app reads them, so a long list only takes longer.
- **Joining a voice room takes time at the client.** A member joining a room of N sends 3N control messages
  at 50 a second: 120 s at 2000. The crypto itself is small: 0.4 ms and about 4 KiB a member.
- **In text channels a writer pays, at its first post.** Following them is one message however many there
  are, and costs nobody else anything. A first post to 2000 online who have no session with the writer comes
  to about 3.6 MB down and 360 KB up for that writer, and its readers can read within seconds. These are
  sums, not yet a measured run.
- **Finding someone's direct conversations reads every kept direct message on the relay,** at each connect, though no channel's:
  at a million of them, about 75 ms on SQLite and 155 ms on Postgres, measured with all of it in memory.
- **Kept history is for 5000 members a channel** (`kept_seats`): the next joiner gets no offline catch-up there. Half of them
  take a seat by following a channel, the rest by asking for one or writing there. It is a guard for a small disk, not a wall: set
  it lower on one. Past about 32,000 a writer's app no longer keeps a copy there, since it can hold no more pins.
- **What kept messages cost the relay,** measured at 2000 and at 5000 members on a desktop NVMe, through the relay's own code, with a
  bare commit at about 3 ms. A post checks the channel's members against who holds its key, so it grows with members. A person does
  not wait for it: the live post goes first.

  | Each | 2000, Postgres | 5000, Postgres | 5000, SQLite |
  |---|---|---|---|
  | Kept post without the commit, p50 / p95 | 2.5 / 10 ms | 4.4 / 13 ms | 17 / 21 ms |
  | Someone left: a writer's next key, p95 | 24 ms | 34 ms | 62 ms |
  | A first post, its largest frame | 32 ms | 31 ms | 38 ms |
  | Worst wait for anything else, 20 new keys a second | 124 ms | 28 ms | 478 ms |

  A disk that stalls shows up in the last line: one run here saw 2.6 s when a bare commit went from 3 ms to over 20 ms. A newcomer's
  first connect takes a seat in each channel: at 2000 members and 300 channels on Postgres about 100 ms, with one run in 40 at 400 ms,
  once per person. On SQLite each writer waits its turn, so during those moments other posts wait too.
- **A channel keeps its newest 10,000 messages** (`kept_window`). The sweep deletes older ones for good, once the posts that
  pushed them out are three days old and have three days left: a raid cleaned up before then, or one on a short timer, takes
  nothing. Lowering it later only takes more; raising it brings nothing back. A big server should set it lower: keys grow with it.
- **What a writer's keys take is counted against `quota_mb`**, a seat's row at half. So seat rows on disk are bounded by
  accounts times that figure, and nothing evicts them: a writer over it stops being kept.
- **A person's pins fit about 32,000 accounts,** in 56 pages of 48 KiB outside the sign-in message, read after it: at 2000 pins
  about 170 KB down at a sign-in, and nothing at a reconnect if the app stayed up and no page moved. People met only in open
  channels stop at half of that. A relay below protocol 21 keeps one item, about 560.

The importer's dry-run warns from these numbers, and stops at none of them: 789 accounts with three badges (a moved
community's members come with badges, so this and not 1598 is its figure), 500 and 2000 online, `max_users`. Past what
one group list holds it keeps the top roles and names the rest. A relay before protocol 21 sends its channel list in one
message, so there the list is fitted by clipping topics, and only then by leaving a named channel out; from 21 on a list
comes in as many frames as it takes. No person is ever a limit: nothing here caps the members of a move.

An import's rows live in `voipc_archive`. 5,000,000 synthetic rows, mean body 70 characters with a long tail, on tmpfs:
so no fsync cost and no cold reads, and these are floors.

| | SQLite | Postgres |
|---|---|---|
| Size with all indexes | 852 MB, 178 B a row | 1,239 MB, 259 B a row |
| Page of 201 rows, newest or deep | 0.15-0.18 ms | 0.2-0.3 ms plus planning |
| Scan 200,000 rows with `LIKE` / `lower() LIKE` | 53 ms | 190-235 ms |
| Batch of 5,000 rows deleted | 16-21 ms | 10-21 ms |
| Whole backup | `VACUUM INTO` 0.9 s, 840 MB, 322 MB under `zstd -3` | `pg_dump -Fc` 13 s, 309 MB |
| After deleting | the file keeps its size; free pages are reused | the same after `VACUUM`; autovacuum handles it |

Discord's rate is what limits a run, never this. Search has no index of its own: it scans a channel, and at most two go
at once.

Not measured: voice in a big channel (`voice_load` is for that), accounts signing in at once, real
networks.

```sh
cargo build -p voipc-server --release --bin voipc-server --example community_load
target/release/voipc-server -c server.toml &   # max_users above N
target/release/examples/community_load run 500 127.0.0.1:9987 "$!"
target/release/examples/community_load frames
target/release/examples/community_load crypto 2000
```

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


## 13. Configuration files

The server listens on port **9987** by default: UDP for the QUIC endpoint every client
connects to, TCP for the browser page. Configure it with a TOML file, which it reads only when
started with `-c` (`voipc-server -c server.toml`; the `admin` and `db` commands need the same
`-c server.toml`, before the command):

```toml
host = "::"               # Bind address — "::" serves IPv6 and IPv4 from one listener; "0.0.0.0" for IPv4 only
tcp_port = 9987           # HTTPS: the browser page, file transfers (and the TCP fallback)
udp_port = 9987           # QUIC endpoint (all clients) — keep equal to tcp_port so one host:port reaches both
tcp_fallback = false      # true: clients that cannot reach UDP carry everything over tcp_port (see below)
max_users = 64
max_connections_per_ip = 32   # A browser client holds two of these, a native client one — so 32 is sixteen browser users behind one NAT
cert_path = "certs/server.crt"
key_path = "certs/server.key"
admin_token = "change-me"  # optional; unset = a random token is printed in the log at every start (with accounts, only while no account is admin)

[files]                    # the encrypted file cache, on by default (§11 has every key)
max_size_mb = 10           # largest file blob
max_age_hours = 24         # no blob stays longer; all of them go at every start

[emotes]                   # the server's emotes and stickers, on by default (§12)
max_total_mb = 32          # all of them, held in memory; each member downloads each once

[update]                   # the relay updating itself, off by default (§14)
enabled = false
delay_minutes = 5          # after it first sees a release
release_candidates = false # also take release candidates
```

> **IPv6:** `host = "::"` is the default and serves both families from one listener (a host with IPv6 disabled falls back to `0.0.0.0` automatically). Do not pin `host` to a concrete IPv4 address while your domain publishes an AAAA record: the browser client then fails while everything else looks healthy, because the page and `/wt.json` are TCP and Chrome quietly falls back to IPv4 after the refused IPv6 attempt, while the WebTransport session is UDP and has no such fallback — it dies with `ERR_QUIC_PROTOCOL_ERROR`.

> **UDP blocked?** Some hosts drop UDP in front of the server (a provider firewall, an
> anti-DDoS filter): the page loads, but every client times out connecting over QUIC.
> `sudo tools/udp-diag.sh` finds where the packets die. Where UDP cannot be opened, set
> `tcp_fallback = true` (or pass `--tcp-fallback`): a client that does not get through over
> QUIC within two seconds then carries the whole session — control, voice, video — through
> a WebSocket on `tcp_port`, the port the page already uses. TCP waits for every lost packet,
> so on a lossy network voice lags more than over QUIC; the status bar says **· TCP** while
> it is in use. Desktop and Android clients dial the fallback on the port they were given,
> so keep `tcp_port` equal to `udp_port`.

> **VPN / multi-homed setups:** If clients connect via a domain name that resolves to a specific IP, set `host` to that IP. Otherwise the server may send QUIC packets from the wrong interface and the handshake never completes. Some options can also be passed as CLI flags (`--host`, `--tcp-port`, `--udp-port`, etc.; `voipc-server --help` lists them).

Runtime settings in `server_settings.json`:

```json
{
  "empty_channel_timeout_secs": 300,
  "max_channels": 50,
  "max_channel_name_len": 32,
  "proximity_enabled": true,
  "game_token": null,
  "server_name": null,
  "server_description": null,
  "new_member_wait_mins": 0
}
```

`max_channels` and `max_channel_name_len` (in characters) bind the temporary channels any member can make. Channels
from `channels.json`, the admin panel and a move from Discord are not counted in `max_channels`, and their names go by
their own limit of 64 characters.

`new_member_wait_mins` (0, off, by default; at most 10080, a week; read at start) holds new members back from speaking, posting and writing direct messages for that long, against raids. An account counts from when it was made; a guest from when that address first came, and a guest counts as new again once the wait and one more day have gone by since their last visit. Someone a move from Discord brought counts from their Discord join date if that covers the whole wait when the import ran, and otherwise from when they open the account. Admins, holders of a privilege and anyone in a group other than the built-in `user` do not wait, so someone you invite into a call cannot talk until the wait ends unless you give them a group, and an invite link that hands one out skips it. A plain group made by a move does not lift it. A guest's clock lives in memory: a restart, a self-update included, starts it again for every guest there. An account's does not. It keeps at most 100,000 addresses: when it is full, a guest from a new address waits from when they connect and again after a reload, and the next sweep, within five minutes, keeps only the clocks still inside the wait.

`server_name` and `server_description` are what the server calls itself on a relay without accounts (on one with them, an admin sets these in the app, which goes first). Shown above the address, never instead of it. A name over 32 characters or shaped like an address reads as none.

`proximity_enabled: false` switches proximity chat off for the whole server: every channel is served as non-positional, requests to enable it are refused, and position beacons are not relayed.

`game_token` (unset by default) is a bearer token a **game server** may present to `POST /game/v1/routes`, which narrows who hears whom inside a channel whose `routed` flag is on. Unset, that endpoint answers 404 and this server has no idea games exist. It is not the admin token and is deliberately much weaker: no session list, no names, no kick, no bans — only "these players may hear each other, for the next few seconds", as opaque ids it forgets.

**Persistent channels** (optional): drop a `channels.json` in the directory the server runs from (or pass `--channels <path>`) to pre-create long-lived rooms that survive restarts. See [channels.example.json](../channels.example.json) — plaintext `password` fields are hashed to SHA-256 on first load and the file is rewritten atomically. A holder of `voipc:channels` standing in such a room can change its password, and can invite someone past it. Per channel:

| Option | Default | Effect |
|---|---|---|
| `proximity` | `"off"` | `"2d"` or `"3d"` makes it a proximity room |
| `hidden` | `false` | Not listed in the sidebar for non-admins. It can still be joined — by an invite link, by the game SDK, or by anyone who knows it is there — so it is out of the way, not locked. Give a channel a `password` if you need it shut, and both if it is the one your game drives |
| `anonymous` | `false` | Members see each other as `Guest-48213907`, a fresh name per visit. The server substitutes it everywhere, so no client ever learns the real one; admins see the real names, and no chat history is handed over in such a channel. Voice channels only, and it hides a name rather than a person: user ids are the same everywhere, so somebody who is also in a channel where you can see them can be matched up by id — which is why a text channel, one you are in *besides* the voice channel you stand in, may not be anonymous at all |
| `screen_share` | `true` | `false` refuses screen sharing there |
| `hide_members` | `false` | Non-admins see no member list, only whoever is speaking (and can still adjust their volume). Nobody outside is told who joins or leaves either — only that the count changed — which is the same rule a password channel follows |
| `routed` | `false` | The server forwards each voice only to whoever should hear it, instead of to every member. For a channel a game drives, where "every member" can be a whole map. **The one option that tells this server anything about who hears whom** — members in such a channel say which of the others they want to hear, and a game server with `game_token` may narrow that further. Positions, names and audio stay as unreadable to it as ever. Everyone joining is told, and the channel is marked **R** |
| `text` | `false` | Makes it a **text channel**: no voice, no screen share, no proximity. Joining one is a subscription rather than a move, so any number can be open at once and none of them costs the voice channel you stand in |
| `message_ttl_secs` | `0` | A **message destruction timer**: seconds a message written here lives before every client deletes it, `0` for none. Up to 30 days. Without accounts the server stores no chat and deletes nothing — this is what the channel tells its members, and each client stamps it on what it sends, inside the encryption where the relay cannot reach it. With accounts, the server also deletes the copies members keep there when their timer runs out. It applies to what is written from then on, not to what people already have |
| `auto_join` | `false` | Only with `text`. Clients follow this channel from their first connect: one frame however many there are, with nobody told, and no keys until someone writes. A user who leaves it is not brought back, nor one who is kicked: the client remembers that, which is why the server joins nobody by itself. Moved channels are marked, and a `*` holder who passes a gate only as `*` enters such a channel by a click. Change it in Server admin → Channels |
| `announce` | `false` | Only with `text`. An **announcement channel**: only its managers — admins and whoever holds the *Channels* privilege (moderators, by default), and for a channel somebody created, its creator — may post, and the server refuses everybody else's messages. It reads none of them; who posts where is all it checks. A member's shared history from such a channel is still shown as second-hand, as everywhere |
| `slow_mode_secs` | `0` | **Slow mode**: each member may post once per this many seconds, up to 6 hours; `0` is off. The server holds them to it, the channel's managers are exempt, and the chat shows the countdown rather than letting a message be sent and refused |
| `nsfw` | `false` | Marks the channel **18+**. Each app asks its user, once per server, to confirm being 18 or older before joining or showing such a channel, and never joins one by itself (`auto_join` waits for that answer). The server only carries the flag. It is a question, not an age check: give the channel a `password` too if it has to stay shut |

The creator of a channel, or any admin or holder of *Channels* (moderators, by default), can change these at runtime through the channel's gear icon. Channels from `channels.json` have no creator, so only those can change them. With accounts, the same dialog sets a channel's gate: the groups that may see and join it, and those that may speak ([ACCOUNTS.md](ACCOUNTS.md), Channel gates).

**Channel presets.** Rather than writing `channels.json` by hand, start from one of the built-in layouts and edit from there:

```bash
./voipc-server channels presets                   # list them
./voipc-server channels init community            # write channels.json from one
./voipc-server channels init roleplay --dry-run   # look first; writes nothing
```

| Preset | For |
|---|---|
| `starter` | A small all-round server: one chat everybody lands in, a few rooms, AFK |
| `gaming` | A friend group or multi-game community: game rooms, a stream room, a proximity campfire, a looking-for-group board with slow mode |
| `roleplay` | A role-play game server: a hidden, locked, routed `Ingame` channel the game drives ([SDK.md](SDK.md)), out-of-character rooms, support and whitelist rooms, staff-only announcements |
| `mmo` | A guild or clan (WoW, FFXIV and co): guild hall, raid comms, party rooms capped at eight, raid sign-ups that expire with the weekly lockout, officers' rooms |
| `competitive` | Shooters and MOBAs: duo, trio, squad and five-stack rooms capped at their size, an in-house lobby with two team rooms, VOD review |
| `tabletop` | Pen & paper: a proximity table the game master shares a map at, a whisper corner, a tavern, lore and character channels |
| `study` | A study group or co-working: a silent room, a proximity library, small group rooms, one-to-one tutoring |
| `lan` | A LAN party or tournament: info and brackets only the orga posts in, match rooms per team, a locked casters' room, a help desk |
| `project` | A team, Slack-style: announcements, team channels, written stand-ups, meeting rooms, a proximity virtual office |
| `family` | Family and friends: a chat everyone lands in, a living room, movie and game nights, a locked corner for the grown-ups |
| `community` | Creators and communities: moderator-only announcements, slow mode, feedback and bug reports, a stage, playtests, and a locked 18+ area |

No preset ships a password: one in a preset would be the same on every server that used it. Every locked channel is given a fresh random one instead, printed once when `init` runs; the file keeps only its hash. Where a layout needs server settings — `roleplay` a `game_token`, `family` and `community` a lower `max_channels` — `init` writes `server_settings.json` if there is none, and otherwise leaves yours alone and prints what to put in it. An existing `channels.json` is only replaced with `--force`, which keeps the old one as `channels.json.bak` (`.bak.2` and so on after that). `--out` writes it elsewhere; `--channels` and `--settings` choose other paths too, but go before the command: `voipc-server --settings path/server_settings.json channels init roleplay`. What comes out is an ordinary `channels.json`: restart the server to load it. A preset copied by hand still says `"<generate>"` where a secret belongs, and the server refuses to start on it rather than lock a channel with a password everybody can read.

## 14. Self-update

With `[update] enabled = true`, the relay keeps itself on the newest release of its major
version. Off by default.

```toml
[update]
enabled = true
delay_minutes = 5          # wait this long after first seeing a release
release_candidates = false # true: also take release candidates (rc.N), and their finals
```

**What it does.**
1. Every 5 minutes it reads the same feed as the desktop apps: the stable one, or with
   `release_candidates = true` the release candidates' one, which carries the finals too.
2. A newer release of the same major version is taken `delay_minutes` after the relay first
   saw it. Releases are published by hand, so the clock starts at the relay, within 5 minutes
   of publishing. A new major version (2.0) is never taken on its own.
3. It downloads `voipc-server-linux-x86_64` and checks its signature: the key the desktop
   updater trusts, for that version and that file. Anything else is refused.
4. It runs the new binary once (`--version`), and copies a SQLite accounts database beside
   the binary as `voipc-server.accounts-before-<version>.db` (the newest two stay; Postgres
   is yours to back up). After a move from Discord each of those holds the archive too, so the
   disk needs room for one more, and an update stops if it cannot make the copy.
5. It keeps the running binary as `voipc-server.previous`, puts the new one in its place,
   tells every client "updating to VoIPC X", and restarts into it in the same process. Calls
   drop; the apps reconnect within seconds.

A release that changes the protocol is taken like any other: apps older than the new protocol
are refused until they update (§8). A step that fails is logged, that version is listed in
`voipc-server.failed` and not tried again, and the relay keeps running.

**What it needs.**
- The linux-x86_64 build (the release binary), not the container (§10).
- A binary the relay's own user can replace: the relay refuses to start with `enabled = true`
  otherwise. The unit of §3 keeps the binary in `/usr/local/bin`, which it cannot write. For
  self-update, keep it in the state directory instead:

      install -d -o voipc -g voipc -m 0700 /var/lib/voipc/bin
      install -o voipc -g voipc -m 0755 voipc-server-linux-x86_64 /var/lib/voipc/bin/voipc-server
      ln -sf /var/lib/voipc/bin/voipc-server /usr/local/bin/voipc-server

  and in the unit, `ExecStart=/var/lib/voipc/bin/voipc-server --config …`. The rest of §3
  stays as it is; `StateDirectory=voipc` keeps that directory writable for the relay under
  `ProtectSystem=strict`. The symlink makes the admin commands run the updated binary too.
- Outbound HTTPS to github.com.

**The trade-off.** With self-update on, the relay's user can replace the binary it runs.
Someone who already runs code as that user could keep it there across restarts. Run the admin
commands as that user (`sudo -u voipc voipc-server …`, as §3 says), never as root.

**When an update does not start.** The new binary marks its first start, and clears the mark
once it serves. A start that finds the mark still set, because the one before it never got
ready, puts `voipc-server.previous` back, lists that version in `voipc-server.failed`, and
starts the previous binary. `Restart=on-failure` (§3) is what starts it again. If the new
binary had already migrated the accounts database, the previous one refuses it: stop the
service, delete `voipc.db-wal` and `voipc.db-shm`, copy
`voipc-server.accounts-before-<version>.db` over `voipc.db`, and start it.

**By hand:** `enabled = false` stops the checks. The binary in place stays whatever it is; put
another one there to go back (§8).
