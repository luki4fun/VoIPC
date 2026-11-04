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

## Groups, privileges and two-factor codes

A **group** is a set of accounts with a name, an optional badge shown next to their
names in the member list, and the **privileges** it hands out. An account can be in
several groups and holds what all of them hand out. Admins manage them in the app:
server menu → *Server admin* → *Users* and *Groups*.

| Privilege | Lets its holders |
|---|---|
| Everything (`*`) | do all of the below, and see the real names behind an anonymous channel |
| Kick (`voipc:kick`) | kick people from the server and from any channel |
| Ban (`voipc:ban`) | ban people they can see, by address and account |
| Ban list (`voipc:bans`) | see the ban list, lift bans, ban an account by name |
| Channels (`voipc:channels`) | change the settings and gates of the channels they can see; post in announcement channels and past slow mode; see hidden channels |
| Emotes (`voipc:emotes`) | add, rename and remove the server's emotes and stickers |
| See accounts (`users:read`) | see the account list, an account's groups and its history, and who is in a group |
| Manage accounts (`users:admin`) | give and take groups, reset two-factor codes, make and revoke invites |
| Manage groups (`roles:admin`) | make, change and delete groups |

Two groups are built in: **admin** (everything) and **user** (every account, no
privileges). The server also makes a **moderator** group (badge *mod*: kick, ban,
channels) on its first start. A moderator group from before 1.7 keeps what it
granted.

- **Privileges need two-factor codes.** A group's privileges, and its badge, apply
  once the account has set up codes. A group without privileges counts at once.
  On a new device, an account with privileges signs in with its password and a
  code; a device the server remembers signs in without either.
- **Nobody hands out more than they hold.** Giving or taking a group, or editing
  one, needs every privilege it hands out, and the account it is done to may hold
  nothing the one doing it lacks. The last admin cannot lose *admin*.
- **A fresh code for steps that hand out power.** Giving or taking a group with
  privileges, making, changing or deleting a group, and resetting someone's codes
  ask for a code from your authenticator app. It holds for ten minutes.
- **Taking a group with privileges away signs the account out**, so the loss
  counts at once; a remembered device signs it in again. Taking away a group
  without privileges does not.
- **Holders of a privilege are spared.** Only an admin kicks or bans an account
  that holds any privilege; in a channel they made, a creator still kicks.
- An account's history in the app lists what was done to its access, by whom and
  when: groups, codes, passwords, devices, invites. It never shows an address.

## Channel gates

A channel can name the groups that may **see and join** it, and the groups that may
**speak** there. Holders of *Channels* set them in the channel's settings; both
empty means everyone, guests too.

- Outside the first list the channel is not there: not in the list, not in a
  member count, "does not exist" when joined, previewed or invited to. Losing the
  group moves its members out, and takes them out of the channel's kept messages,
  online or not.
- Outside the second list a member listens and reads. The server drops their
  voice, posts and screen shares there, and the app says *Listening only*.
- Admins pass every gate. A holder of *Channels* changes only gates of channels
  they can see, and cannot save one that shuts themselves out.
- The gate of a channel from `channels.json` is kept in the accounts database and
  outlasts a restart; one on a channel somebody made lasts as long as the channel.
- A group a gate names cannot be deleted: change the channel first. Deleting it
  would open what it closed.
- Known limit: making a channel with the name of one you cannot see is refused as
  "name taken", which tells you that a channel of that name exists.

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

- `voipc-server admin grant <name> <group>` gives a group (`admin`, `moderator` or
  any other), and `admin revoke <name> <group>` takes it away again. A group with
  privileges taken away signs the account out everywhere (the last admin keeps
  *admin*).
- `voipc-server admin reset-2fa <name>` removes an account's codes and recovery
  codes, forgets its devices and signs it out everywhere. This is how an admin who
  lost their phone gets back in.
- `voipc-server db backup <path>` copies a SQLite database while the server runs,
  readable by its owner only. For Postgres, use `pg_dump`. Keep the key file with
  the copy.

These commands are a second process next to the server. A running server checks
every signed-in connection against the database every five minutes, so a group
given or taken away, codes reset or a session ended from the shell reaches
connections that are already open within that time. What is done in the app
counts at once.

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
  will not export, and reloading a tab signs a remembered account back in by
  itself, without voice; a new tab, or a tab you disconnected or that another
  device took over, shows the connect dialog. *Your account → Forget* drops it on
  this device.
- **One device at a time.** Signing in somewhere else ends the older session; it
  does not reconnect by itself.
- **Copies on the server** are asked about once, the first time you connect, and
  can be changed under *Your account*. On the desktop your messages are also kept
  in its encrypted archive, unless you switched that off; the browser keeps none
  between visits, so there the server's copy is the only one, and a reload reads
  the newest 500 entries of each conversation back from it. With it you can
  read your channels on another device, and catch up on what people wrote while
  you were away; somebody online gets a direct message kept for them at once. It
  works
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
- groups, what they hand out, and which groups each gated channel names
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

- Starting a direct conversation with an account that has not been online since
  you connected.
- Keeping chat in the browser between visits. The browser keeps the server's copies
  only; the desktop app keeps its own encrypted archive. So after a reload the
  browser shows only what has a copy: whoever writes a message decides that, so
  messages from a guest, or from somebody with copies off, are gone. It also
  forgets what you had not opened yet (a read conversation and an unread one look
  the same), and a pin by a manager who is away.
- A kept copy of a direct message you write from an anonymous channel: the copy
  carries your account and the message your pseudonym, so nothing is kept there,
  edits and deletions included, and the app says so. A key for that conversation
  may still be filed the first time, which a modified client of the other party
  could notice; the same user id on another roster tells them as much.
