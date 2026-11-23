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
  sign-ins over the fallback (guests and browsers are unaffected). How it shows: apps' right
  passwords read as wrong (the relay cannot tell the two apart), remembered devices are refused as
  "not made on this connection", and the relay logs `device key sign-in refused: not made on this
  connection` (also `login key refused` and `provider proof refused`). An account from before
  1.12 still gets in there with its old secret, and cannot move to its login key.
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
- **Database connections** (`db_connections`, 32): a sign-in is a few writes, and a write waits for the database's
  disk. The more writes are waiting together, the more each flush carries, so this is how fast a relay signs people
  back in after a restart. Postgres' own `max_connections` (100) has to hold it with everything else on that database.
  Past them, sign-ins wait their turn for up to 10 s, then the app tries again a moment later. §10a has the numbers.
- **Password sign-ins** (`password_sign_ins_per_15min`, 1000, everyone together): each new device signs in with the
  password once; a remembered device signs with its key and is not counted. The cap holds off guessing spread over many
  addresses, and once it is spent no new device signs in until the 15 minutes end. 1000 is about one a second: raise it
  for a move or a big first evening, lower it while such guessing runs. Per address it stays 30.
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
  -d voipc` from the dump), then, with the service still stopped,

      sudo -u voipc voipc-server --config /etc/voipc/server.toml db new-incarnation

  and start it again. Test a restore once, before you need one.
- **`db new-incarnation` (1.14) belongs to every restore.** A channel's group key moved on after the copy was made, and
  whoever left since was taken out of it there, which the copy does not know. The command marks the database as restored:
  at its next start every channel with a key starts a new generation and its members are seated again, as after the
  switch to the group key (§10a has what a re-seat costs). Members' apps see the new start as made anew. If it is
  forgotten, an app whose keys are ahead of the database proves it with a signed header the relay can check, and the relay
  starts that channel anew itself, at most once an hour, only on a header signed by one of the channel's keyholders now;
  for a copy older than the channel's current generation it cannot check that, and only warns in the Load tab ("a member
  reports it ahead of this database"), and it warns the same for a header signed by a keyholder the copy does not hold
  or no longer counts among them. What kept history the copy
  holds stays readable.
- **A restore puts back whoever left or was removed since the copy.** Their seat returns with the rest. On the live path
  writers' apps hand them keys again at their next post, each named as it happens; under the group key they are seated
  again in the new generation, and in a gated channel named to its writers, until someone removes them again.
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

**From 1.12 to 1.13** (protocol 23 to 24):
- **Apps first**, as for any protocol: a 1.13 app talks to the 1.12 relay meanwhile.
- No migration and no new keys. A device remembered again (a password or provider sign-in on a
  device that already was) now drops its old device key at once; on 1.12 those stayed until the
  90-day sweep.

**From 1.13 to 1.14** (protocol 24 to 26; 25 was never released):
- **Apps first**, as for any protocol: a 1.14 app talks to the 1.13 relay meanwhile, without the group key and
  without edges there.
- **A migration:** `0013_group_keys.sql` adds the group key's tables. Going back takes the old binary and the backup.
- **The group key is on by default** (`group_key`, §13; [GROUP-KEY.md](GROUP-KEY.md)). At the first start no channel has
  keys yet, and each makes them at its first use: the first member who needs one asks, a volunteer's app starts the
  channel's keys, and members are seated as they read or write. An account that keeps a channel's history is seated for
  it from the first time one of its devices signs in with a 1.14 app; kept posts written under the group key before then
  are not readable to it. What the channel kept before the update stays readable as before. Desktop apps help hold keys
  unless their user turns that off; browsers and guests only as a last resort.
- **`group_key = false` keeps 1.13's paths**: the live path in text channels and the 3N join in voice rooms, and the
  relay still serves what the key kept, read-only. A start with it on again after a run with it off starts every
  channel's keys anew, a full re-seat, so leave it as it is unless the group key is what fails you.
- **A restore now ends with `db new-incarnation`** (§7).
- **Keys whose defaults change something:** `[media] voice_room` (250): a voice room over 250 refuses the next joiner
  until its limit or this is raised; `db_connections` (32, was 10). One channel message holds at most 16 KiB in voice
  rooms too, as it always did in text channels. Every new key is listed in
  [COMPATIBILITY.md](COMPATIBILITY.md) §3, "What changed in 1.14".

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
      -p 9987:9987/tcp -p 9987:9987/udp ghcr.io/luki4fun/voipc-server:1.12.1
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

A relay for tens of thousands asks for 64 MiB: give it `33554432` (Linux doubles it) instead.

At 2000 clients on this machine that took the packets dropped from 340,000 to under 11,000 a run, and all of them joining a
channel from about 3 s to about 1 s. `nstat -az UdpRcvbufErrors` counts what the kernel has dropped this way.

The relay also says so itself. In a minute when anything happened, it writes one line: who is online, connects refused
and why, setups that failed, how sessions ended, and the datagrams dropped on its own socket, for example
`last minute: 1998 online; ended: closed by peer 3, timed out 1; refused: per-IP limit reached 2; UDP datagrams dropped 412`.

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
- **Joining a voice room took time at the client** before the group key, and still does with `group_key = false`: a
  member joining a room of N sends 3N control messages at 50 a second, 120 s at 2000, though the crypto itself is small
  (0.4 ms and about 4 KiB a member). Under the group key a join is one welcome from the room's keyholders.
- **On the live path a writer in a text channel pays, at its first post.** Following them is one message however many
  there are, and costs nobody else anything. A first post to 2000 online who have no session with the writer comes to
  about 3.6 MB down and 360 KB up for that writer, and its readers can read within seconds. These are sums, not yet a
  measured run. Under the group key (the default) a post costs its writer the post and, once an epoch, about 230 bytes,
  however many read it; the channel's keyholders carry the rest (below).
- **Finding someone's direct conversations reads every kept direct message on the relay,** at each connect, though no channel's:
  at a million of them, about 75 ms on SQLite and 155 ms on Postgres, measured with all of it in memory.
- **Kept history is for 5000 members a channel** (`kept_seats`): the next joiner gets no offline catch-up there. Half of them
  take a seat by following a channel, the rest by asking for one or writing there. It is a guard for a small disk, not a wall: set
  it lower on one. Under the group key those accounts are seated in the channel's group at once, online or not, and that is
  cheap to raise: a seat costs a keyholder one welcome of about 1.7 KB and a 60-byte row, and 100,000 seats took two minutes
  (below). On the live path, past about 32,000 a writer's app no longer keeps a copy there, since it can hold no more pins;
  the group key has no such limit.
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
  Under the group key it is also what bounds the channel's key material: the relay keeps each epoch a kept message was
  written in, its seals (about 97 KB at 100,000 members) and the rows of its buckets, until the sweep takes the last message
  of it. At 100,000 members and the default, that is estimated at 1.6 to 6 GB a channel, by how often epochs change
  ([GROUP-KEY.md](GROUP-KEY.md) §5.10); it was not measured yet.
- **What a writer's keys take is counted against `quota_mb`**, a seat's row at half. So seat rows on disk are bounded by
  accounts times that figure, and nothing evicts them: a writer over it stops being kept. Under the group key, the rows a
  writer who shares history gives newcomers (1,629 B at each of its chains no link reaches) are not counted: the relay
  keeps them only for newcomers it owes an answer, and bounds them per seat taken instead, to those chains plus 4 rows:
  about 8.1 KB at 5 such chains, and at most about 1.4 GB from one sharer that makes chains on purpose, at the default
  `quota_mb` ([GROUP-KEY.md](GROUP-KEY.md) §8).
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

**Since 1.14 the lobby is not sent whole**, which was what made a join cost the relay more the more people were
online. Measured on the same machine, 2026-11-16, guests connecting and staying (`community_load run N … --idle S`),
load clients on the same machine:

| Clients | Relay CPU to let them in | Relay RSS | Each | Connect p95 | Datagrams dropped |
|---|---|---|---|---|---|
| 5,000, before 1.14 | 197 s | 1,177 MiB | 241 KiB | 21 ms | 1,621 |
| 5,000 | 7.9 s | 558 MiB | 114 KiB | 2 ms | 0 |
| 10,000 | 17 s | 1,111 MiB | 113 KiB | 1 ms | 0 |
| 25,000 | 103 s | 2,554 MiB | 104 KiB | 8 ms | 0 |
| 50,000 | 158 s | 4,169 MiB | 85 KiB | 3 ms | 0 |

An idle relay of 25,000 used 0.28 of a core. With text channels on the live path (`community_load follow`), the relay
killed with `kill -9` halfway and started again: 10,000 were all back in 57 s, 25,000 in 89 s. At 25,000 with posts
going out, every post to that many readers comes back as that many acknowledgements at once. An 8 MiB buffer dropped
them: 750,000 datagrams, and 1,159 people who could not come back while their old session waited out its timeout. With
`rmem_max` at 32 MiB (64 MiB given) nothing dropped while posting, 52,600 dropped in the minute everyone came back
after `kill -9` (2,585 handshakes tried again), and nobody was lost: give such a relay the larger buffer above.

Signing back in after a restart, with accounts on Postgres (`community_load seed`, then `run --accounts`): 50,000
accounts with remembered devices arriving 2,000 a second, as after a relay restart. The relay keeps up as long as its
database does, at 2.6 ms of relay CPU a sign-in. What the database does is its disk's flush:

| Database | Signed in | Wait p95 |
|---|---|---|
| 10 connections, before 1.14 (busy refused at once) | stalled at 9,300 in a minute: every refusal came back as a new handshake | — |
| 10 connections, waiting their turn | 17,700 in 350 s; the rest gave up | 274 s |
| 32 connections, five runs | 50,000 in 51, 92, 141, 148 and 166 s, by how long the disk's flushes stalled (up to 100 s, this machine's btrfs) | 27 to 146 s |
| 32 connections, `synchronous_commit = off` | 50,000 in 38 s, as fast as they came | 14 ms |

Put a big relay's Postgres on a disk whose flushes are quick and steady (a server SSD that protects its cache on
power loss), or set `synchronous_commit = off` for its database: a crash of Postgres then loses the last moment of
writes, never the database, and a sign-in lost that way is made again.

Screen shares (`share_load`, one HD share at 7.5 Mbit/s, 30 frames a second, viewers on the same machine):

| Viewers | Sent to them | Frames a second each | Relay CPU | Datagrams dropped |
|---|---|---|---|---|
| 100 | 0.8 Gbit/s | 30 | 0.3 of a core | 0 |
| 500 | 4.1 Gbit/s | 31 | 2 cores | 0 |
| 1,000 | 8.5 Gbit/s | 32 | 4.4 cores | 0 |
| 2,000 | 11.5 of 15 Gbit/s | 22 | 10 cores | 197,000 |
| 500 over 5 shares | 4.2 Gbit/s | 32 | 4.5 cores; 2.3 with 4 threads | 0 |

So a relay sends about 1,000 HD viewers before its network port is full, and its processor follows at about half a
core per Gbit/s. `[media]` (§13) keeps it under what its port carries, and media edges (§10b) carry the rest.

Through media edges (1.14), measured 2026-11-18 on the same machine, everything on loopback: the relay held to 4 CPUs
(`taskset -c 0-3`, so 4 threads), each edge to 4 of its own (2 physical cores; `max_viewers` 1000, `egress_mbit` 8000),
`share_load` on the other 16, one HD share at 7.5 Mbit/s and 30 frames a second for 30 s, `local_first` 8, `rmem_max` at
32 MiB. A Firefox tab took about one core beside it, on no CPU of its own. The 2,000 run was made once with one load
generator and once split over two of 1,000, each on CPUs of its own: both got every frame, and no generator went above
43% of its CPUs, so the tool was not the limit there. The 3,000 run was split over three.

| Viewers | Relay CPU, RSS | Each edge's CPU, RSS | Generator CPU, of its CPUs | Frames whole | Latency p50 / p95 | Refused | Datagrams dropped |
|---|---|---|---|---|---|---|---|
| 1,000, the relay alone | 2.2 cores, 206 MiB; 8.9 Gbit/s out | – | 20% of 16 | 100% | 13 / 17 ms | 0 | 0 |
| 1,000, 1 edge (992 on it) | 0.03 of a core, 160 MiB | 2.2 cores, 156 MiB | 20% of 16 | 100% | 13 / 17 ms through the edge, 0 / 1 ms on the relay | 0 | 0 |
| 2,000, 2 edges, one generator | 0.04 of a core, 339 MiB | 2.5 cores, about 227 MiB | 41% of 16 | 100% | 16 / 22 ms | 0 | 0 |
| 2,000, 2 edges, two generators | 0.04 of a core, 341 MiB | 2.5 cores, up to 460 and 397 MiB | 43% and 42% of 8 | 100% | 16 / 22 ms | 0 | 0 |
| 3,000, 3 edges, three generators | 0.14 to 0.26 of a core, 584 MiB | 3.3 to 3.5 of its 4 CPUs, about 830 MiB | 61 to 74% of 5 or 6 | 73% | 175-186 / 397-417 ms | 0 | 210, 3,086 and 0 at the edges, 0 at the relay |

(The relay's 0.04 with two generators is 0.18 counted over the first generator's window, which takes in the second's
arrivals.) A `kill -9` of one edge, 15 s after every viewer was watching:

| Setup | The relay saw it go | Where its viewers went | Refused | Last frame to the next, p50 / p95 / max |
|---|---|---|---|---|
| 2 edges, 1,000 viewers | after 6.03 s ("timed out") | 496 to the other edge | 0 | 7.17 / 7.18 / 7.19 s |
| 1 edge, 1,000 viewers | after 6.01 s | 992 back to the relay, which then used 1.03 cores | 0 | 6.07 / 6.08 / 6.08 s |

So with edges a big share costs the relay its feeds alone: 0.04 of a core for 2,000 viewers on two edges, where 1,000 on
the relay alone took 2.2 cores. An edge costs what the relay alone would: 2.2 to 2.5 cores and 160 to 460 MiB for 1,000
HD viewers. The extra hop costs nothing measurable here: 1,000 viewers through an edge saw 13 / 17 ms, as 1,000 on the
relay alone did. In the 3,000 run only 73% of frames came whole, with 22.5 Gbit/s over loopback and each edge at about
85% of its CPUs. Why is not proven: most likely this one machine carrying a relay, three edges and 3,000 viewers at
once, but only edges and viewers on machines of their own can tell that apart from a limit of the edges.

Not measured: edges and viewers on other machines and real networks (none were available here), more than one share
through edges, and Firefox and the desktop and Android apps watching through an edge. Chromium is, in the `EDGE=1`
lane of `test-web.sh`.

Voice (`voice_load 1000 127.0.0.1:9987 90 --rooms 20 --speakers 3`): 20 rooms of 50 people, three talking in each,
147,000 packets a second to listeners. Loss was 0.001% (packets in flight at the ends) and the socket dropped none.
The relay's CPU depends on how many threads it wakes, not on the work:

| Relay threads (`TOKIO_WORKER_THREADS`) | Relay CPU |
|---|---|
| 2 | 0.9 of a core |
| 8 | 3.3 cores |
| 32, one per core here (the default) | 4.1 cores |
| 32, held to 2 cores (`taskset -c 0-1`) | 0.85 of a core |

The loss was the same in each run, so the extra CPU goes to the threads themselves (no profile yet says where). On a
relay that mostly carries voice, `TOKIO_WORKER_THREADS=4` in its environment saves that. A relay that signs thousands
in at once needs the cores (2.6 ms each, above). The screen-share CPU above ran with 32 threads, which costs it about
twice what 4 do.

Not measured: one voice room at its limit of 250, real networks.

**The group key (1.14)**, measured with `group_load` on the same machine, 2026-11-19, relay and load clients together,
every keyholder an app's own duty building its commits whole, the way the desktop app does. A re-seat is bound by its
Join commits one after another (at most 256 seats each, 391 at 100,000), not by the keyholders' processors:

| What | Seats | Took | Relay RSS | Relay CPU | Database |
|---|---|---|---|---|---|
| Offline accounts that keep the channel's history, seated at once (`seats N`), SQLite | 5,000 | 4.8 s | 48 MiB | 0.4 s | 44 MB |
| the same | 20,000 | 13.1 s | 90 MiB | 2.1 s | 165 MB |
| the same | 50,000 | 27.6 s | 150 MiB | 9.1 s | 404 MB |
| the same | 100,000 | 117 s | 269 MiB | 30.2 s | 804 MB |
| the same, Postgres | 100,000 | 118 s | 250 MiB | 23.1 s | 605 MB |
| Guests connecting 1,000 a second and reading (`storm N`), no accounts | 50,000 | 52 s, each seated within 0.3 s (p95) | 4,976 MiB | 104 s | – |

- The 100,000 runs include a stall of about 30 s, from the relay queueing each eager seat against the whole queue; that was
  fixed after these runs (a seat index on the join queue) and they were not made again. Below 100,000 it cost little.
- A keyholder spends about 28 ms building a Join of 256 and 10 ms more on its due's frames, mostly checking the 256
  joiners' signatures: 15 s of keyholder CPU for a 100,000 re-seat. Each keyholder held about 50 MiB at 100,000.
- A refresh at 100,000 builds in about 60 ms and sends 0.85 MB: about 10 MB an hour from the keyholders.
- A keyholder's leaving is a full re-key: 3.6 s of build at 100,000. With guests leaving and coming back 20 a second for two
  minutes (`exits 20`) and two writers posting each second, no post was dropped at 5,000 to 100,000 seats, and each member
  took about 3.3 MB an hour, almost all of it the posts. Being seated costs a member 4 to 5 KB.
- A relay's group memory is about 1.8 KB a guest seat (88 MB at 50,000). A reconnect storm of 50,000 guests is bound by
  admission, as without the key: 189 Joins and one opening took 8.7 s of keyholder CPU, and nothing was missed. In that run
  up to 8% of guests whose first ask came while the group's inbox was full stayed unseated until their next post; the apps
  have asked again by themselves since, also not measured again.
- In a browser a keyholder builds in steps of 2 ms in a call or while hidden, 8 ms otherwise: a cold re-key of 10,000,
  about 0.8 s of work, ran as about 400 steps, the longest 5.3 ms; a Join's due still takes about 22 ms of the page at once
  for its joiners' signatures ([GROUP-KEY.md](GROUP-KEY.md) §8 has the browser's numbers). A browser holds text keys for at
  most 10,000 seats; above that only desktops do.
- Not measured: a storm of 100,000 guests (it would need about 38 GiB here), keyholders on other machines, phones, and the
  key material `kept_window` keeps.

The Load tab (*Server admin*) shows a row for each group of at least 1,000 seats and for any group with something amiss, at
most 50: its seats, keyholders online and in all, the age of its last commit, joins and exits waiting, missed deadlines, and
about what it holds in memory and in the database. It shows a commit as soon as the relay has queued it to the members,
a moment before their apps take it. Its warnings name the channel: no keyholder online for some minutes, keys
late (no new epoch for 70 minutes), missed deadlines, and a member reporting the channel ahead of this database (a restore
without `db new-incarnation`, §7). On a relay with accounts, a text channel that keeps its history (not an anonymous one or one
that hides its members) waits, when its keyholders are all away, before a volunteer starts its keys anew: not at all
where every keyholder was a browser or a guest (a volunteer starts anew as soon as none is online and someone waits to be
seated or to leave), unless a new start began that set within the hour, else an hour. Other text channels, voice rooms,
and every channel on a relay without accounts start anew at once. A channel whose keyholders changed 2048 times starts
anew too, once, so that every member can still follow its keys.

```sh
cargo build -p voipc-server --release --bin voipc-server --examples
target/release/voipc-server -c server.toml &   # max_users above N
target/release/examples/community_load run 500 127.0.0.1:9987 "$!"
target/release/examples/community_load run 5000 127.0.0.1:9987 "$!" --rate 200 --idle 60   # memory per connection
target/release/examples/share_load 500 127.0.0.1:9987 "$!" --shares 1 --mbit 7.5 --fps 30   # [media] above what it asks
target/release/examples/voice_load 1000 127.0.0.1:9987 90 --rooms 20 --speakers 3
target/release/examples/community_load frames
target/release/examples/community_load crypto 2000
target/release/examples/group_load seats 20000      # the group key; starts a relay of its own (port 29900), --database postgres://… for Postgres
target/release/examples/group_load storm 20000
target/release/examples/group_load exits 20 --guests 20000
```

With edges (`edge-core.toml` is `server.toml` with `[pool] edges = { e1 = "…" }`, `e1.toml` that edge's file, §10b),
each process on CPUs of its own:

```sh
taskset -c 0-3 target/release/voipc-server -c edge-core.toml & relay=$!
taskset -c 4-7 target/release/voipc-server -c e1.toml edge & edge=$!
taskset -c 16-23 target/release/examples/share_load 1000 127.0.0.1:9987 "$relay" --edge-pids "$edge" --secs 34 &
sleep 3   # the first one's share is up
taskset -c 24-31 target/release/examples/share_load 1000 127.0.0.1:9987 "$relay" --edge-pids "$edge" --shares 0 --first 1000
```

## 10b. Big screen shares

A relay sends each viewer of a share a copy of its own, so its network port is what a big share meets first: about 1,000
HD viewers on 10 Gbit/s (§10a). Two things keep that in hand.

**The caps, on every relay** (`[media]`, 1.14, §13):
- `share_viewers` (100): the viewers of one share this relay serves itself.
- `video_egress_mbit` (1000, a 1 Gbit port): the video it sends in all, counted at each share's resolution: 7.5 Mbit/s a
  viewer at 1080p, 4 at 720p, 2 below. Give it what the port carries with room to spare for voice and the rest, about
  8000 on a 10 Gbit port.
- A viewer past either is told the share is full, or that the server is sending all the video it can, with a Retry.
  Nothing else changes, and the sharer's own share goes on.

**Media edges** (`[pool]`, 1.14) carry more. An edge is the same `voipc-server` binary, run as `voipc-server -c edge.toml
edge`, best on a machine and a port of its own. It links to the relay over the relay's own UDP port, proves itself with a
secret both hold, and forwards the shares the relay places viewers on: the relay sends it one copy of each, and it sends
one to each viewer there.
- **Who goes where.** The first `local_first` (8) viewers of each share stay on the relay, which is no farther away than
  an edge. The next go to the edge with the most room, each up to its `max_viewers` and `egress_mbit`; one already
  carrying that share is picked if it is close, which saves the relay a copy. The relay counts one copy per edge
  against its `video_egress_mbit`. Where no edge has room, the relay serves the viewer itself, up to its `[media]` caps,
  and refuses only past those; one of the first that the relay has no room for goes to an edge already carrying the
  share, which costs the relay nothing more. A viewer on the TCP fallback always stays on the relay. With edges, `share_viewers` is
  the relay's own part of a share, not the whole.
- **What an edge has.** A UDP port for its viewers, and nothing else: no TCP port, page, accounts, files, emotes,
  channels, bans or operator certificate. It makes a certificate of its own, renewed every 7 days, which viewers trust
  by the hash the relay sends them, so an edge needs no DNS name or public certificate.
- **What an edge sees.** The address of each viewer it serves, when they watch, and each frame's size and timing. Never
  a name, a channel or a key: the sharer's app seals every frame ([THREAT-MODEL.md](THREAT-MODEL.md)). It does see each
  share's sharer by session id, which is the sharer's user id: whoever runs an edge and also joins the relay (as a
  guest, where guests may) can look that up to a name, and to the channel if they can see it. Still, run it where you
  would run the relay. The relay logs each edge's address when it links (edges are infrastructure, not
  users); an edge logs viewer addresses at `debug` only.
- **When one goes away.** A stopped edge tells its viewers and the relay at once; a crashed or cut-off one the relay
  notices within 6 s. Either way its viewers go to another edge or back to the relay at once, and only those nobody has
  room for are refused (6.1 s back on the relay, 7.2 s on another edge, in §10a). A viewer whose edge sends no whole
  frame for 10 s asks the relay to move it, and is not sent to that edge again for 60 s; while the share itself sends
  nothing (its sharer's network stalls), nobody is moved. Nobody is moved back to an edge that returns.
- **What edges do not carry:** voice (it never leaves the relay), and the sharer's upload. An edge is picked by its
  room, not by where it or the viewer is.

**How many a setup carries.** Estimates from §10a, not measured on separate machines: each machine with a 10 Gbit port
used to about 80% (an edge's default `egress_mbit` of 8000), HD at 7.9 Mbit/s on the wire, so about 1,000 HD viewers
a machine, and 5 big shares. The relay's `[media]` is raised to match (`share_viewers` 1000, `video_egress_mbit` 8000).
With its defaults (100 a share, 1000 Mbit/s) the relay itself adds at most about 130 HD viewers in all, not 1,000, and
its budget has to hold its feeds too: one copy per share per edge, the last column.

| Setup | HD viewers | What the relay sends its edges |
|---|---|---|
| The relay alone | about 1,000 | 0 |
| 1 edge | about 2,000 | 37 Mbit/s |
| 3 edges | about 4,000 | 112 Mbit/s |
| 10 edges | about 11,000 | 375 Mbit/s |

An edge took 2.2 to 2.5 cores and 160 to 460 MiB per 1,000 HD viewers (§10a). A 720p share counts 4 Mbit/s a
viewer and a smaller one 2, so an `egress_mbit` of 8000 has room for 2,000 or 4,000 of those: raise the edge's
`max_viewers` (1000) to use it, if its processor keeps up. Smaller shares were not measured.

**Setting one up:**
1. Make a secret for the edge: `openssl rand -base64 32`. Each edge has its own.
2. On the relay, in `server.toml`, then restart it:

   ```toml
   [pool]
   local_first = 8                          # the first viewers of each share stay here
   edges = { fra1 = "<that secret>" }       # name = secret, one per edge
   ```

   A name is 1 to 32 of `a-z`, `0-9` and `-`, and is what the Load tab shows; a secret has at least 32 characters.
   `local_first` may not be above `[media] share_viewers`.
3. On the edge's machine, `/etc/voipc/edge.toml`, every key with its default where it has one:

   ```toml
   core = "voice.example.org:9987"   # the relay's host and UDP port; an IPv6 address in brackets, as [2001:db8::1]:9987
   # core_fingerprint = "AB:CD:…"    # see below; required when core is an IP address
   name = "fra1"                     # its name in the relay's [pool] edges
   secret = "<that secret>"          # and its secret there
   host = "::"                       # the address viewers' QUIC is bound on
   udp_port = 9987                   # where viewers connect
   public = "fra1.example.org:9987"  # host:port viewers reach udp_port at; the relay sends it to them
   max_viewers = 1000                # viewers at once
   egress_mbit = 8000                # the video it may send; the relay places no more on it
   max_shares = 16                   # shares it is fed at once, 1 to 64
   max_connections_per_ip = 32       # at least 2
   ```

   The edge checks the file before it starts and names what is wrong. An unknown key stops it, `[update]` too: edges are
   updated by hand.
4. **Trusting the relay.** Unset, `core_fingerprint` leaves it to the public CAs: the relay's certificate must be issued
   for `core`'s name, as a Let's Encrypt one is. Set it to what `voipc-server -c server.toml cert fingerprint` prints on
   the relay (colons optional) when that certificate is self-signed or `core` is an IP address. It pins that one
   certificate: after every renewal the edge cannot link (its log says so) until it has the new fingerprint, so do not
   pin a certificate that renews by itself.
5. **The secret stays in two files.** Keep both readable by the `voipc` user only:

       useradd --system --no-create-home --shell /usr/sbin/nologin voipc   # if this machine has none
       install -d -m 0755 /etc/voipc
       install -o voipc -g voipc -m 0600 edge.toml /etc/voipc/edge.toml
       chown voipc:voipc /etc/voipc/server.toml && chmod 0600 /etc/voipc/server.toml   # on the relay

   Neither process logs a secret, and a printed config shows `<secret>`.
6. **Network.** Open the edge's `udp_port` inbound: viewers connect there, over QUIC. The edge dials out to the relay's
   UDP port, which is open already, so the relay needs no new rule. Behind NAT, forward that UDP port and put the outside
   address in `public`. An edge asks for the same UDP buffers as a relay: set `rmem_max` and `wmem_max` as in §10a.
7. **systemd:**

   ```ini
   # /etc/systemd/system/voipc-edge.service
   [Unit]
   Description=VoIPC media edge
   After=network-online.target
   Wants=network-online.target

   [Service]
   User=voipc
   Group=voipc
   ExecStart=/usr/local/bin/voipc-server -c /etc/voipc/edge.toml edge
   UMask=0077
   Restart=on-failure
   # and every line of §3's unit from NoNewPrivileges=yes to LimitNOFILE=65536, as they are there

   [Install]
   WantedBy=multi-user.target
   ```

   `-c` goes before `edge`, as for every command. An edge writes nothing, so it needs no `StateDirectory` or
   `WorkingDirectory`. `systemctl enable --now voipc-edge`, and `systemctl stop` tells its viewers before it goes.
8. **Check it.** The relay logs `edge fra1 linked from <address> (pool v1, …)`, the edge `linked to the core at … as fra1`,
   and the Load tab lists it as linked. Until it links, its viewers are served by the relay.

**Running them.**
- **The Load tab** (*Server admin*) lists every edge in `[pool]`, linked or not: its address and pool version, the
  viewers and shares the relay gave it against its limits, the Mbit/s given and what it last said it sent, its processor
  and memory, and how old its last report is, with frames it dropped. Each share says how many of its viewers are on
  edges. It warns when an edge has been away for more than a minute, carries 90% of its viewers or its video, or when
  feeds to edges dropped frames (the way from the relay to its edges is too slow). While an edge is not linked, it also
  says when something naming itself that edge was refused for its pool version: unproven, since an edge of another pool
  version cannot show its secret, so check that edge's own log.
- **Logs.** The relay: `edge fra1 offline (why); N viewers moved, M refused` when one goes. The edge: its link going up
  and down with the reason, and in a minute when anything happened one `last minute:` line: viewers, shares, Mbit/s,
  frames dropped, tickets refused and why, and datagrams its socket dropped.
- **Upgrading: the relay first, then its edges.** A relay and an edge talk when they speak the same pool version, whatever
  their releases (1.14 speaks 1; both log it when they link); the client protocol has nothing to do with it. A relay
  refuses an edge of another pool version, and says in its log and the Load tab which one to update. That edge logs an
  error and asks again every minute, and until it is updated the viewers it would carry are served by the relay. Edges
  do not update themselves: verify the new binary (§1), put it in place and restart them.
- **Restarting the relay** ends every edge's link; they link again by themselves, at most 30 s after it is back, and
  viewers come back as after any restart.
- **Removing an edge, or one whose secret got out:** delete its line in `[pool] edges` and restart the relay. There is no
  reload. A stolen secret lets its holder pose as that edge (which shuts the real one out) and get the shares the relay
  places on it, still sealed, and send the apps of the viewers placed on it to any host and UDP port it names, as a
  hostile relay could: one connection each, which shows that host their address.
- **A new secret:** change it in both files, and restart both.

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
`-c server.toml`, before the command, and a media edge reads a file of its own, `voipc-server -c edge.toml edge`, §10b):

```toml
host = "::"               # Bind address — "::" serves IPv6 and IPv4 from one listener; "0.0.0.0" for IPv4 only
tcp_port = 9987           # HTTPS: the browser page, file transfers (and the TCP fallback)
udp_port = 9987           # QUIC endpoint (all clients) — keep equal to tcp_port so one host:port reaches both
tcp_fallback = false      # true: clients that cannot reach UDP carry everything over tcp_port (see below)
group_key = true          # the group epoch key in every text channel and voice room (1.14, docs/GROUP-KEY.md); false keeps 1.13's paths
max_users = 64
live_lobby = 2000         # While General holds at most this many, an app showing its list hears each join there by name; above it, counts and pages
max_connections_per_ip = 32   # A browser client holds two of these, a native client one — so 32 is sixteen browser users behind one NAT.
                              # Mobile carriers put thousands behind one address: raise it on a big public relay
                              # (each 32 more also lets that address handshake and connect that much faster)
cert_path = "certs/server.crt"
key_path = "certs/server.key"
admin_token = "change-me"  # optional; unset = a random token is printed in the log at every start (with accounts, only while no account is admin)

[media]                    # what screen shares and voice rooms may cost (1.14, §10b)
share_viewers = 100        # viewers of one share on this relay (its edges carry more); one more is told it is full
video_egress_mbit = 1000   # video sent, all shares together, counted at each share's resolution (1080p 7.5, 720p 4, less 2 Mbit/s), one copy per edge fed
voice_room = 250           # people in a voice room that names no limit (0: none); routed rooms keep none

[pool]                     # media edges for big screen shares, none by default (1.14, §10b)
local_first = 8            # the first viewers of each share stay on this relay; at most share_viewers
# edges = { fra1 = "<openssl rand -base64 32>" }   # name = secret, as in that edge's edge.toml; keep this file 0600

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
`voipc-server.accounts-before-<version>.db` over `voipc.db`, run `voipc-server --config …
db new-incarnation` if the previous version knows that command (1.14 and later; one before the
group key has no group key tables to start anew), and start it. The relay's log says the same.

**By hand:** `enabled = false` stops the checks. The binary in place stays whatever it is; put
another one there to go back (§8).
