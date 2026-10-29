# Accounts and kept messages

A VoIPC server works without accounts: people pick a name, talk, and the server
forgets everything when it restarts. Accounts are something a server's operator
turns on. Then people can keep a name, admins and moderators get two-factor codes,
and every member can choose to keep encrypted copies of their messages on the
server. Messages written while somebody was away are then waiting for them when
they come back.

The server never reads those messages. This page covers how to set accounts up,
how they behave, and what the server learns.

## Turning accounts on

In `server.toml`:

```toml
[accounts]
mode = "optional"                 # off | optional | required
database = "sqlite://voipc.db"    # or postgres://user:pass@host/db
registration = "invite"           # open | invite | closed
cloud = true                      # let members keep copies of their messages here
retention_days = 365              # copies go after this, or sooner by their own timer
quota_mb = 50                     # per account
key_file = "voipc-accounts.key"   # made on first start; VOIPC_ACCOUNTS_KEY overrides it
```

`--accounts optional` and `--database <url>` do the same on the command line.

- **`mode`**: `off` (the default) opens no database at all. `optional` lets guests
  in next to accounts: an account's name is reserved, so a guest cannot use it, and
  guests keep their `#tag`. Nor can a guest use a name that spells an account's once
  its letters from other scripts are read as the Latin ones they look like (a
  Cyrillic `а` for `a`): the server answers "that name looks like an account's on
  this server". A name with a letter that looks like no Latin one (`ü`) passes,
  and so do look-alikes made of Latin letters and digits (`a1ice`). `required` refuses guests.
- **`database`**: SQLite suits a small server and needs nothing else. Use Postgres for
  a big one. Both are built into the same binary.
- **`key_file`**: seals the two-factor secrets. It is made on first start with
  permissions 0600. **Back it up with the database**: without it, nobody's
  two-factor codes work any more. The database remembers which key it was made
  with: the server refuses to start with another one, and does not make a new
  key file next to an existing database. Give `database` and `key_file` full
  paths: started from another working directory, relative ones open a new, empty
  database there, with a new key, and every account seems gone.

## The first admin

Start the server. Sign-up needs a code unless `registration = "open"`, so print
yourself one first: `voipc-server -c server.toml admin invite` (with `--for
<name>` when it is `closed`). Sign up in the app, then enter the admin token
(status bar → shield, or the server menu). While no account is an admin, the
token makes yours one, and you set up two-factor codes right away. From then on
the token is refused on that server; admins are accounts.
`voipc-server -c server.toml admin grant <name> admin` does the same without the
token.

## Who can sign up

- **`open`**: anyone. The app solves a small proof-of-work puzzle first, and each
  address can make a limited number of accounts a day.
- **`invite`**: sign-up needs a code. Print one with
  `voipc-server -c server.toml admin invite` (valid 7 days; `--days 1..30`).
  The code goes in *Create account → Invite code*. Each code makes one account.
- **`closed`**: the same command with `--for <name>` makes a code that only that
  name can use. That is how an admin makes an account for somebody; in this
  mode `admin invite` refuses to print a code without `--for`. Codes printed
  before the switch to `closed` stay valid until they expire.

## Roles and two-factor codes

There are two roles: **admin** (everything) and **moderator** (kick, ban, and any
channel's settings). Either role needs two-factor codes before its rights apply.
On a new device, the account signs in with its password and a code; a device the
server remembers signs in without either.

A moderator kicks and bans people, not admins or other moderators. Listing and
lifting bans stay with admins.

A ban covers the address someone connects from (an IPv4 address, or the IPv6
/64), and with *Ban the account too* their account, from any address. Everyone
behind a banned address is kept out, except accounts that hold a role here: they
are let in after they sign in. The database keeps a keyed hash of a banned
address, never the address, so the list shows the name the person used. An
admin can also ban an account by name from *Active bans*, and the shell can:
`voipc-server ban add --account NAME` (or `--ip ADDR`, `--reason`, `--days`),
`ban list`, `ban remove ID`.

From the server's shell. Each command reads `[accounts]` from the server's own
config, given before the command — `voipc-server -c server.toml admin invite` —
and without it stops with "accounts are off":

- `voipc-server admin grant <name> admin|moderator` gives a role, and
  `admin revoke <name> admin|moderator` takes it away again and signs the account
  out everywhere (the last admin keeps the role).
- `voipc-server admin reset-2fa <name>` removes an account's codes and recovery
  codes, forgets its devices and signs it out everywhere. This is how an admin who
  lost their phone gets back in.
- `voipc-server db backup <path>` copies a SQLite database while the server runs,
  readable by its owner only. For Postgres, use `pg_dump`. Keep the key file with
  the copy.

These commands are a second process next to the server. A running server checks
every signed-in connection against the database every five minutes, so a role
given or taken away, codes reset or a session ended from the shell reaches
connections that are already open within that time.

## For members

- **One password, one recovery key.** The app derives everything from your password:
  the secret the server checks, and the key to your vault. The password itself never
  leaves your device. A new account is shown a recovery key once; write it down.
- **A new password.** *Your account → Password: Change* asks for the current one,
  and for a code when two-factor codes are on. *Forgot your password?* in the
  connect dialog sets a new one with the recovery key instead, again with a code
  when codes are on. Either way the server signs out every other device and
  forgets every remembered one; the device you did it on is remembered again. The
  vault, your identity (and what others pinned of it) and the recovery key stay as
  they were.
- **Only the recovery key resets the password.** Since 1.3 the recovery key also
  derives a reset key; the server keeps its public half and checks every reset
  against it. A remembered device holds the key to your vault, but not this one, so
  it cannot set a new password. An account made before 1.3 has no reset key until
  you make a new recovery key (*Your account → Recovery key: New*, with your
  password, and a code when codes are on; the old recovery key stops working). Until
  then a device that holds the vault key could reset it, as before 1.3.
- **A password for this server only.** What the app derives is salted with the id
  the server gives itself, and a server could give itself another server's id:
  with one password on both, it would get what signs you in there. The desktop app
  remembers which id each address had and refuses a server that claims an id it
  knows from another address (*Forget the account id of …* in the connect dialog,
  for a server that really moved). The browser does the same for the servers you
  open from one server's page; each page keeps its own list.
- **Remembered devices.** After you sign in with your password, the app asks the
  server to remember this device. Next time it signs in without the password. On
  the desktop the device is kept in the encrypted chat history: it signs in alone
  once that history is unlocked, and with chat history switched off only until
  the app closes. In the browser, the device key is kept under a key the browser
  will not export. *Your account → Forget* drops it on this device.
- **One device at a time.** Signing in somewhere else ends the older session; it
  does not reconnect by itself.
- **Copies on the server** are asked about once, the first time you connect, and
  can be changed under *Your account*. On the desktop your messages are also kept
  in its encrypted archive, unless you switched that off; the browser keeps none
  between visits, so there the server's copy is the only one. With it you can
  read your channels on another device, and catch up on what people wrote while
  you were away. It works
  in channels from the server's `channels.json` and in direct messages. Temporary
  channels, and channels that are anonymous or hide their members, keep nothing.
- **People who join later.** What you kept in a channel before somebody joined is
  theirs to read unless you say no: it is the switch *Share recent channel chat
  with newcomers* in Settings, which is on by default and ticked in the copies
  question. With it on, someone who joins gets the keys to everything you kept in
  that channel, not only recent chat. With it off, they read from the moment they
  joined.
- **Who can read what you keep** is said in the channel, by name, when your app
  hands them a key. If a name there is new to you, the server added a member you
  did not see join. The server cannot add a reader to your messages without that
  notice on the device that hands the key over.
- **Leaving ends it.** Leaving a text channel, or being kicked from it, takes you
  out of its log: the server does it, and every writer's next message there is
  under a new key you do not get. What you already have stays yours. Moving
  between voice channels keeps their logs; *Stop keeping this channel's messages
  for me* (under the chat's bin) ends one until you come back to it.
- **Deleting what you kept.** The bin in a conversation offers *Clear here, and
  delete what I wrote from the server's copy*: your messages there go from the
  server, and a tombstone, signed like a message, asks the readers' devices to
  drop their copies too. *Your account → Messages you kept here: Delete* removes
  them from every conversation (without tombstones). Either way, copies people's
  devices already have may stay, and a server can hold a tombstone back, though
  it cannot make one up.
- **Deleting your account.** *Your account → Delete account…* asks for the name,
  the password and, with codes on, a code. The vault, the messages the account
  kept, its keys, its memberships, sessions and remembered devices go from the
  server; the name is free for someone else, and people who pinned the old
  account are told the new one is another account. What others wrote to you
  stays theirs until it expires, and so do their copies of what you wrote. The
  last admin cannot delete itself: make another admin first.
- **Kept copies follow the channel's rules.** In an announcement channel only its
  managers' copies are kept, slow mode paces copies as it paces posts, and a copy
  is only kept from inside the channel.
- **Verify identity** in a member's menu shows a safety number for the two of you.
  Compare it in person or on a call. If it matches, nobody stands between you,
  including the server. When somebody's identity changes, you are told — also when
  they are away, when a name you know turns up as a different account (deleted
  and taken again, say), and when an account you know shows up as a guest.
  While the conversation runs on another key than the one pinned, there is no
  number to compare: reconnect to them first.

## What the server learns

From accounts:

- account names
- an Argon2id hash of a secret derived from each password
- identity public keys
- the public keys of remembered devices
- two-factor secrets, sealed by the key file
- roles
- sign-in records with hashed IP addresses
- each account's vault, which it cannot open without guessing the password: each
  guess costs 600,000 PBKDF2-SHA256 rounds, so a long password used nowhere else
  is what protects it
- bans: a keyed hash of each banned address (never the address), and banned
  accounts

From kept messages:

- who wrote in which channel or direct conversation, when, and how long each message is
- each kept message's destruction timer, so it can delete the copy on time (for a
  direct message, the timer you chose)
- which channels each account keeps

It never learns the text or a key. The full list is in the README under
*Data Transparency*.

Sign-in lines in the server's own log name the address an account signed in
from; keep that log as you would keep the database.

Two trade-offs come with kept messages:

- **They are signed.** The people they are for can prove you wrote them.
- **They have no forward secrecy.** Whoever later gets into a member's account can
  read what that member could read.

**Browser caveat:** the browser client is served by the server itself. A server
that turns hostile can change the page. It can read what you type there, and use
what this browser keeps for your account — the remembered device key and the key
to your vault — to sign in as you and read everything kept for you. The desktop
app does not have that problem.

## What a server that turns hostile can still do

The encryption keeps the text and the keys from the server. The server still
holds the vault, the member lists and the copies, so it can (the whole table is
in [THREAT-MODEL.md](THREAT-MODEL.md)):

- **drop or roll back what it holds**: hide copies, or give a device an older
  copy of your vault, or none (an older or missing list of pinned identities
  lets it introduce itself as somebody you have not met yet on that device). A
  device that saw a newer copy before warns and does not save over it;
- **withhold or replay kept copies**, but not forge or alter one: each is signed
  by its writer;
- **guess your password offline**, at the cost above;
- **decide who is a member** of a channel's log: a member it made up gets keys
  only with the notice above, and that notice is shown on the device that hands
  the key over;
- **keep a writer on an older key of their own** that still reaches somebody who
  left, which helps it only together with that person;
- **name accounts as it likes**: names are bound to people only through what
  your app pinned when it first met them, which is why a known name under a new
  account is reported;
- **meet you first**: the first time two people meet, nothing is pinned yet.
  Safety numbers are how you find out;
- **reach the other servers in its page**: in the browser, the page comes from
  the server you opened, and that page handles every server you add in the same
  tab, their remembered device keys included. For an account on another server,
  open that server's own page, or use the desktop app.

## Limits

- 50 MB of kept messages per account by default (`quota_mb`). One message can be up
  to 16 KiB sealed.
- A channel keeps messages for up to 256 accounts.
- A device fetches the newest 400 keys handed to it in a channel. In a busy
  channel with many people coming and going, older copies past those can no
  longer be opened on a new device.
- `retention_days` caps how long a copy stays. A message's own timer can only make
  that shorter.

## Not in this version

- An admin dialog in the app. Roles, invites and two-factor resets are on the
  command line for now.
- Starting a direct conversation with an account that has not been online since
  you connected.
- Keeping chat in the browser between visits. The browser keeps the server's copies
  only; the desktop app keeps its own encrypted archive.
