# A stand-in Discord

Written by hand from the structures in Discord's API docs (docs.discord.com/developers, read on
2026-11-04). Nothing in here was ever sent by Discord, every name and id is made up, and no test
or lane calls Discord: `voipc_import::mock::Mock` answers from these files, with no socket and no
real host. So this shows what the docs say, not what Discord does. Fields can differ in the real
thing, which is why `model.rs` gives everything a default and why the owner's run against a test
server is the only check of that.

Every id is past 2^53, as real ones are. The first files' ids are from about 2024. What is new in
`v2/` has ids from the year 2040, so that it counts as made after any run a test or a lane makes.

## What the files answer

| File | Route |
|---|---|
| `me.json`, `app.json`, `guilds.json` | `/users/@me`, `/applications/@me`, `/users/@me/guilds` |
| `guild.json`, `bot-member.json` | `/guilds/{g}`, `/guilds/{g}/members/{bot}`. Anyone else's `/members/{id}` is their row of `members-*.json`, or a 404 |
| `channels.json`, `roles.json`, `role-counts.json` | `/channels`, `/roles`, `/roles/member-counts` |
| `members-*.json`, `bans-*.json` | `/members`, `/bans`: all of a kind put together, paged by `after` |
| `emojis.json`, `stickers.json` | `/emojis`, `/stickers` |
| `threads-active.json`, `threads-archived-<channel>-*.json` | `/threads/active`, `/channels/{c}/threads/archived/public` |
| `messages-<channel or thread>-*.json` | `/channels/{c}/messages`: the `limit` right after `after`, newest first in the page |
| `search.json` | `/messages/search`: a channel listed with `indexing` first answers 202. Otherwise the count of its messages, or `total_results` if given |
| `rate-script.json` | With `use_rate_script`: which call of which route answers 429 (user, shared, global), 403 or 500 |
| `blank-page.json` | Not a route: a page as Discord sends it with Message Content off |
| `v2/` | With `use_v2`, what a delta sees: a file of the same name replaces, and `messages-*` add |
| `v2/resend.json` | Not a route: the row someone deleted, for `import_replay` to send straight, as no walk gets back to it |
| `plan.json` | Not a route: what the dry-run makes of all this, for the wizard's selftest. A test keeps it true: `VOIPC_WRITE_PLAN=1 cargo test -p voipc-import the_wizards_plan` |

Thousands of rows are never committed: `Mock::big(members, bans, roles, channels)` makes them, and
`Mock::add_messages` tops up a channel. `Mock::deny_everyone` closes one between two reads.

`crates/voipc-server/examples/import_replay.rs` runs a whole import of these files against a running
relay, over QUIC, with the importer's real driver. Its first lines say how.

## The traps in it

- **Names:** text `general` and voice `General`; text `lounge` and voice `lounge`.
- **Roles:** one named `Admin` with no ADMINISTRATOR, and one with the bit and no members. One named
  `-`. A bot's own managed role. `Muted`, denied writing in `#general` and seeing `#after-dark`. 20
  `Team` roles allowed into `#teams`.
- **Channels:** `#staff`, gated, with a rule for one member. `#vault`, which nobody passes. `#news`,
  an announcement channel only Moderators write in. `#old-logs`, seen without its history. A forum,
  a media channel, a stage and a directory. `#music`, where only one role could stream.
- **Threads:** a forum post whose first message has the thread's id, a thread started from a
  message, archived ones, one in `#staff`, and a private one.
- **People:** `frank`, whose username is `admin`; `gina`, still in Membership Screening; a bot;
  `nell`, with a null join date; an ex-member, `zed`; `Deleted User`; a webhook.
- **In `#lounge`:** a reply, a pin, reactions, a long body, a spoiler, an emote, one of an emote
  that does not come, system messages, a file with Discord's address on it, a sticker, a poll, a
  forward, an embed, code holding what looks like a mention, a mention of a private channel.

## Who to sign in as

For a lane, with the stand-in provider's subject set to one of these:

| Name | Discord id |
|---|---|
| `dan_d`, in Moderators, Staff and Regulars | 1190000000000001001 |
| `eva.e`, in Regulars and Team 01 | 1190000000000001002 |
| `bea_b`, in Regulars | 1190000000000001003 |
| `cal`, in no role | 1190000000000001004 |
