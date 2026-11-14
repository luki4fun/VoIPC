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
modlog_days = 180                 # rows of the moderation log go after this
archive_days = 0                  # what came from Discord goes at this age; 0: until removed
unclaimed_days = 90               # an account the move made goes if unopened; 0: never
quota_mb = 50                     # per account
kept_window = 10000               # a channel's copy goes once this many newer have stood 3 days
kept_seats = 5000                 # accounts a channel keeps messages for; 0: no limit
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

**Invite links** (*Server admin → Users → Invite links*, for `users:admin`) let many
people in with one link, for a post or a website: with a limit of people, an expiry
if you want one, and optionally a group they start in. A link is public by nature,
so each sign-up still solves the proof of work and counts against the sign-up limits,
and it is shown once and revocable. Its starting group must hold no privileges, Share history aside, then
and at each use: give that group power later and the link stops handing it out. On
`closed` there are none. A link works for sign-up with a password or through a provider,
and an invite code from an admin works through a provider too, also where sign-up is
otherwise by invite only.

**An account the move from Discord made** can be opened on `invite` and `closed` too: it
was made already, and needs no code ([An account the move made for you](#an-account-the-move-made-for-you)).

## Groups, privileges and two-factor codes

A **group** is a set of accounts with a name, an optional badge shown next to their
names in the member list, and the **privileges** it hands out. An account can be in
several groups and holds what all of them hand out. Admins manage them in the app:
server menu → *Server admin* → *Users* and *Groups*.

| Privilege | Lets its holders |
|---|---|
| Everything (`*`) | do all of the below, and see the real names behind an anonymous channel |
| Kick (`voipc:kick`) | kick people from the server and from any channel they can see |
| Ban (`voipc:ban`) | ban people they can see, by address and account, and remove the posts of someone banned |
| Ban list (`voipc:bans`) | see the ban list, lift bans, ban an account by name, and remove the posts of someone banned |
| Restrict (`voipc:restrict`) | mute someone's voice or time them out, for a while, if they hold no more than the one doing it |
| Hide messages (`voipc:hide`) | hide a message from its readers, who can still open it; not held back by slow mode |
| Take reports (`voipc:reports`) | receive what people report, and be named to whoever reports. Spares nobody from a kick |
| Moderation log (`voipc:modlog`) | read who did what to whom. Spares nobody from a kick |
| Channels (`voipc:channels`) | change the settings and gates of the channels they can see; delete one made in the app, with a code, unless it holds what came from Discord; post in announcement channels and past slow mode; see hidden channels; invite people to a room they stand in |
| Emotes (`voipc:emotes`) | add, rename and remove the server's emotes and stickers |
| See accounts (`users:read`) | see the account list, an account's groups and its history, and who is in a group; not those banned on Discord, which are `*`'s |
| Manage accounts (`users:admin`) | give and take groups, reset two-factor codes, make and revoke invites |
| Manage groups (`roles:admin`) | make, change and delete groups; a group's colour and its place in the order |
| Profiles (`voipc:profiles`) | clear the display name and picture of someone holding no more than they do. For someone who has gone, that is on the Users tab, which also takes *See accounts*. Everyone connected is told |
| Call on everybody (`voipc:mention_all`) | use `@everyone`, `@here` and a group's `@&badge`. Spares nobody from a kick. Everyone connected, guests too, can see who holds it while they are connected |
| Share history (`voipc:share_history`) | turn on *Share recent channel chat with newcomers*: answer newcomers' requests with recent chat, and let those who join read what you kept before. No group holds it until an admin gives it, not even *moderator*. Needs no codes. Spares nobody from a kick |

Two groups are built in: **admin** (everything) and **user** (every account, no
privileges; give *user* Share history and every account may share, each once they turn it
on themselves). The server also makes a **moderator** group (badge *mod*: kick, ban,
restrict, hide messages, moderation log, take reports, channels) on its first start.
A moderator group from before 1.7 keeps what it granted. One still holding exactly
kick, ban and channels gains the other four once, on the first start of 1.10, and the
server's log says so. A group someone has edited is left as it is, and a privilege
taken away afterwards stays away.

- **Privileges need two-factor codes.** A group's privileges, and its badge, apply
  once the account has set up codes. A group without privileges counts at once. Share
  history is the one exception: it gives no power over anyone, so it applies at once, and a
  group holding only that counts at once.
  On a new device, an account with privileges signs in with its password and a
  code; a device the server remembers signs in without either.
- **Nobody hands out more than they hold.** Giving or taking a group, or editing
  one, needs every privilege it hands out, and the account it is done to may hold
  nothing the one doing it lacks. So whoever manages accounts or groups needs Share history
  too, to manage those who hold it. The last admin cannot lose *admin*.
- **A fresh code for steps that hand out power.** Giving or taking a group with
  privileges, making, changing or deleting a group, resetting someone's codes, and
  removing a banned member's posts ask for a code from your authenticator app. It
  holds for ten minutes.
- **Taking a group with privileges away signs the account out**, so the loss
  counts at once; a remembered device signs it in again. Taking away a group
  without privileges does not.
- **Holders of a privilege are spared.** Only an admin kicks or bans an account
  that holds a privilege; in a channel they made, a creator still kicks. Holders of only
  calling on everybody, taking reports, reading the log or sharing history are not spared, here or wherever
  else this page spares a privilege.
- **Share history binds honest apps.** The server's word decides only whether your own switch
  counts here: it can say you hold the privilege or not, and it cannot turn the switch on. A
  modified app can hand over what it holds anyway, as anyone can paste it, and it is still
  shown as that member's word. So the mark in the member list says who is worth asking, and
  vouches for nothing. Taking the privilege away stops new hand-outs: what was handed over
  stays handed over.
- **Mute and timeout** (`voipc:restrict`, from someone's menu). A mute stops their voice
  and screen share. A timeout stops those and their posts too, reactions, pins, edits and
  deletes included, as well as pokes, invites, new channels, and setting a display name or
  picture; clearing their own stays open. Neither reaches direct messages, so someone timed
  out can still write to a moderator. Neither takes reading, joining or keys, nor files
  they upload or a privilege they hold: a restriction limits speech, and a privilege
  stays until the group is taken. It outlasts a reconnect and a restart, and ends when it
  runs out or someone lifts it from the same menu. Everyone sees that the person is held, by
  whom and until when; only they and holders of `voipc:restrict` see why. Setting one and
  lifting one each write a row in the moderation log; running out does not.
- **Who a restriction binds.** Whoever holds `voipc:restrict` acts on anyone holding no
  more than they do, Share history aside, an admin on anyone. Nobody else acts on themselves, so a moderator who
  is held cannot lift it. An account's goes with the account. A guest has none, so theirs goes
  by address: it binds every guest at that address or IPv6 /64, under any name, and no
  account there, nor an admin there by the server's token. Everyone connected sees a mark on
  each of those guests, so anyone can see that they share an address, though not which, also
  when one of them goes by a pseudonym; a moderator could do it to find that out. It ends
  within a day, because addresses change hands. A guest off posts who connects again goes
  by `guest` and their tag, not the name they asked for, since a name is public text.
- **The wait for new members**, `new_member_wait_mins` in `server_settings.json` and off by
  default ([OPERATING.md](OPERATING.md)), holds voice, posts and direct messages for that
  long from when an account was made, or a guest first came from an address. A guest
  counts as new again once the wait and one more day have gone by since their last visit.
  An admin, the holder of a privilege of the spared kind, and anyone in a group other than the built-in `user`
  do not wait, so giving a group ends it at once. It writes nothing in the log, and only
  giving a group ends it early: a moderator's lift does not. An invite link that hands out a
  group skips it.
- **Hiding a message** (`voipc:hide`, from a message's menu). It collapses to "Removed by
  whoever did it", with *Show anyway*, for everyone reading that channel; *Restore* takes it
  back, and the latest of the two wins. Nothing is deleted: the message stays in every
  copy, and anyone can open it. It stays out of search, pins and Files while hidden,
  cannot be forwarded or copied from the menu, and an honest app hands it to nobody
  asking for the channel's past. Only an admin hides what someone holding a privilege wrote,
  as with a kick. It does nothing in a direct conversation, and is neither offered nor
  obeyed in an anonymous channel, where it would unmask the moderator as staff: kick and
  ban do the work there.
- **How far a hide reaches.** It is an end-to-end message like any other: the server cannot
  read it, so each app decides whether it counts, against who the server says holds
  what. The server tells everyone, guests too, every account holding a privilege other than
  calling on everybody, taking reports, reading the log or sharing history, by id and without
  names, and who among those connected may call on everybody. So a hide still counts when the moderator has gone offline, and stops
  counting for an app that reads it again after the moderator lost the privilege: a browser
  shows such a message again, while a desktop's archive keeps what it decided. Word of a
  change to someone offline can take up to five minutes to arrive. People away read it
  from the channel's stored log, as they do any message, which takes a channel that
  keeps messages and a moderator with copies kept here. Otherwise it reaches only whoever is
  online, and the action says so before and after. A guest, or a reader without copies
  kept here, has only what happens while they are online. A stored hide sits under the
  moderator's own key, so someone who joins the channel after it reads the message unhidden
  until that moderator's app is next running, and for good if that moderator does not share,
  which is how every moderator starts. An admin who wants stored hides to reach newcomers gives
  moderators Share history, and each still has to turn it on.
- **Removing a banned member's posts** (`voipc:ban` or `voipc:bans`), in the ban dialog as
  *Also remove their posts*, under *Ban an account*, and on each row of *Active bans*. It
  only works on someone banned now, so nobody in good standing is wiped quietly: an account
  needs its own ban, so the dialog bans the account too. It goes back an hour, a day or
  seven days, and only an admin goes further or takes everything kept. Only an admin
  removes the posts of someone holding a privilege, an admin having banned them. It takes a
  fresh code, asked for where you are, whether the admin panel is open or not. A moderator
  cannot delete their own row of it, and it looks to them like it does to everyone.
- **What a removal does and does not do.** It deletes for good what this server keeps of
  their channel messages, and writes one row of the moderation log saying how many went, or
  does neither. It does not delete a direct message, which is the other party's too and may
  be the record of what got them banned. It cannot delete copies on people's devices: every
  connected app is told, and every app connecting later for as long as the log keeps the
  row, and collapses its copies to "This server says *whoever* removed this with a ban",
  with *Show anyway*. Those copies stay out of search, pins and Files, and an honest app
  hands them to nobody. *Restore* does not lift it. It does not undo when the ban ends or
  is lifted, and someone back from a ban can write again as before. Files they attached
  are not deleted at once: the server does not know who posted a file, and it goes when it
  ages out. A device away for longer than `modlog_days` is not told.
- **Active bans** come a hundred at a time, with *Show more* and a search by the name a row
  shows. Who stands behind a pseudonym stays there: a search finds the name you can see.
- **What a limited window can bring back.** A delete or an edit is a message of its writer's,
  kept like any other. When the window takes their delete or edit but not the older message
  it applied to, a device reading the log anew, a browser after a reload or a new device,
  shows the older text again, not collapsed, since the removal does not reach back that far.
  Their request that devices drop what they wrote can go the same way, and a device that had
  not read it yet keeps those copies as they are. Taking everything kept has no such gap.
- **A guest has nothing kept here**, so removing a guest's posts only asks devices to hide
  what they hold under that name. So does removing by a pseudonym, the only name a moderator
  has for someone in an anonymous channel, also when an admin made the ban: asking by any
  other name answers as for someone not banned, so a moderator cannot try names against it.
  An admin asks by the account, which does delete. Its row keeps to the pseudonym with no
  account, and so does what every app is told, then and later, so no device hides that
  account's copies. Only that admin's own answer has the real name.
- **Where the line comes from.** The server says it, not the moderator's app: that is how
  it reaches every channel, also those the moderator cannot see, and people offline. So the
  name on it is the server's word, which nobody signs, and a hostile server could put anyone's
  name on any channel message. That costs a false line and one extra click, never a message.
- An account's history in the app lists what was done to its access, by whom and
  when: groups, codes, passwords, devices, invites. It never shows an address.
- **Inviting someone to your room** (`voipc:channels`, *Invite to Channel* in their menu)
  works in any room you stand in, made by anyone or from `channels.json`. They get the
  popup anyone's invite raises, naming you, and nothing happens until they accept, so
  nobody is ever moved. Accepting passes the room's password, which holding this privilege
  lets you change anyway; a gate still holds, and someone outside it is not asked and hears
  no name, and neither is a full room or an 18+ question skipped. It cannot be done from
  behind a pseudonym, in an anonymous room or beside one, since the invite would say who
  that is. You hear the answer, not the room's creator. Each invite writes a row in the
  moderation log; asking again before an answer does not. An invite stays good until it is
  answered or they disconnect, also after you have left the room.
- **Reports** (`voipc:reports`, or everything). What someone reports comes to you as a
  direct message from them, under a line: "Report from carla. They say dan wrote this in
  #lobby at 14:02", with their reason beside it as plain text. That line is their word, and
  so is the message: nothing signs what was said. The one check there is, is your own
  copy of that channel, and the line says what it found: *matches your copy*, *your copy
  says otherwise*, *your copy was edited since*, or *you have no copy, nothing proves it*.
  A copy a member handed over counts as none, and so does anything said in a direct
  message. There is no shared queue: each of you has a row per reporter, and answering is
  writing back. To work one as a team, forward it into a staff channel, where it stays a
  report and says who passed it on. A flood of reports is a flood of direct messages:
  block them, restrict or kick them. Who a report is from is who sent it, however it is
  labelled, and one that a member hands over with a channel's history is a plain forward.
  Taking the privilege away, or going behind a pseudonym, takes you off the list at the
  next ask.
- **Who is named.** Whoever reports sees the names of those who take reports, up to five,
  those online first and in no fixed order. Someone away is named only to an account, on a
  server that keeps messages, and only with a log key and no ban. So holding this
  privilege is not a secret from members. Nobody behind a pseudonym is named, here or
  away, since the list pairs a user id with a real name.

**A group's colour and order** decide how its badge looks and where its people stand
in the member list: under their top group, top groups first. A row shows its top
three badges. A group's *Own section in the member list* can be turned off: its people
then stay with everybody else and only wear the badge. Holding `roles:admin`, you can
recolour only groups you could have made,
and a group you could not stays exactly where it is in the order, with nothing moving
past it. **A badge is public**: everyone on the server is told every badge, guests too,
whoever holds it. What the group behind it is called is not.

**Groups the move from Discord made** ([MOVING.md](MOVING.md)) come in two kinds. A role's
plain group has its badge, colour and order, and hands out nothing, so nobody gains a privilege
by what Discord said. An admin can add Share history to such a group, and only that. If that role could do something on Discord, a second group,
`<role>-power`, holds the matching privileges and is given to nobody until an admin presses OK
for that person, with a code. The first is what the claim gives; the second waits. A later
import follows Discord for a plain group's badge, colour and order, and leaves its name, since
gates go by the name.

### The moderation log

*Server admin → Moderation log* shows who did what to whom, to holders of
`voipc:modlog`. A row is written for a kick from the server, a ban (one row, also when
it covers both an address and an account) and a lifted ban, in the app or from the
server's shell, a moderator's kick from a channel, a cleared profile, a deleted
channel, a banned member's posts removed, and a moderator's invite to a room. On a server moved from Discord
([MOVING.md](MOVING.md)) also each run that begins and ends, an undo, someone left out of the move or let back in, an
admin's OK or no to someone keeping what they could do on Discord, naming them, posts deleted from what came from
Discord, and accounts nobody opened removed after `unclaimed_days`. A channel's creator kicking or inviting someone takes no privilege and writes
no row. Each step writes its row first: if the row cannot be kept, the step does not
happen. A hide and a restore are different: the server cannot see them, so the row is
the moderator's own app saying so, marked as such. It can be left out by a changed app,
and at most 120 of one moderator's stay per hour.

- **Nobody can change or delete a row from the app**, and the relay has no step that
  would. This protects against moderators, not the owner: whoever holds the database
  can change it.
- **Rows go after `modlog_days`** (180 by default), by time alone. That is also how long
  the names in them stay: a row keeps the names of the accounts it mentions after those
  accounts are deleted, so that a ban can still be explained. A device's address is
  never in it.
- **It keeps what was masked masked.** Someone behind a pseudonym is written down by the
  pseudonym with no account, whoever acted on them, an admin too. An admin's ban shows
  the real name in the ban list to admins only; anyone else with the list sees the
  pseudonym there too. An admin's removal of their posts deletes by the account too, and
  still says only the pseudonym to everyone else.
- **The reason for a restriction** shows only to a reader who also holds `voipc:restrict`,
  as it does on the person's mark. Every other row's reason shows to every reader.
- **A channel shows by name only to someone who can see it**: an admin, or someone its
  gate lets in, and for a channel that hides its members only an admin. To everyone
  else the row says "a channel you cannot see now", and a deletion's own row names no
  channel. A temporary or deleted channel shows to admins only. The row itself is there for
  every reader.
- **Hiding a message is the moderator's own word.** The relay cannot see inside
  messages, so its row only says what the moderator's app reported, and is marked so. It
  always names the account that sent it, so it cannot accuse anyone else, but a modified
  app could leave it out or make it up. There are at most 120 such notes an hour for
  each account, and they never push another row out.

Giving someone `voipc:modlog` alone spares them nothing: they can still be kicked.

## Channel gates

A channel can name the groups that may **see and join** it, and the groups that may
**speak** there. Holders of *Channels* set them in the channel's settings; both
empty means everyone, guests too.

- Outside the first list the channel is not there: not in the list, not in a
  member count, "does not exist" when joined, previewed, invited to or kicked from.
  Whatever else someone tries on it, by its id or its log's name, answers as for no
  channel at all. Losing the group moves its members out, and takes them out of the
  channel's kept messages, online or not.
- Outside the second list a member listens and reads. The server drops their
  voice, posts and screen shares there, and the app says *Listening only*.
- Admins pass every gate, by a click: their app follows a text channel by itself only
  where their groups let them in, and nobody is pulled into one silently. A holder of
  *Channels* changes only gates of channels they can see, and cannot save one that
  shuts themselves out.
- The gate of a channel from `channels.json` is kept in the accounts database and
  outlasts a restart; one on a channel somebody made lasts as long as the channel.
- A group a gate names cannot be deleted: change the channel first. Deleting it
  would open what it closed. The refusal names the channel only to someone who can
  see it.
- Known limit: making a channel with the name of one you cannot see is refused as
  "name taken", which tells you that a channel of that name exists. And trying to
  delete a group that a channel you cannot see names tells a holder of *Manage
  groups* that such a channel exists, not which.

A ban covers the address someone connects from (an IPv4 address, or the IPv6
/64), and with *Ban the account too* their account, from any address. Everyone
behind a banned address is kept out, except accounts that hold a privilege here
(the spared kind, above): they are let in after they sign in. The database keeps
a keyed hash of a banned
address, never the address, so the list shows the name the person used. An
admin can also ban an account by name from *Active bans*, and the shell can:
`voipc-server ban add --account NAME` (or `--ip ADDR`, `--reason`, `--days`),
`ban list`, `ban remove ID`. By name, as in a kick, only an admin can ban someone
who holds privileges. A banned account leaves every channel's stored log, so it gets
no key written after that; it joins again like anyone else if the ban is lifted.

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
connections that are already open within that time. Someone away who lost a group
there leaves its channels' kept messages as they next sign in, or within the hour.
What is done in the app counts at once.

## For members

- **One password, one recovery key.** The app derives everything from your password: a key
  it signs your sign-ins with, and the key to your vault. Neither the password nor anything
  that stands in for it leaves your device: since 1.12 the server keeps only that signing key's
  public half, and each signature names the connection it was made on, so a server you were
  lured to cannot pass your sign-in on. An account from before 1.12 moves to this the first
  time it gives its password to a 1.12 app: a sign-in with it, or confirming it on a device
  signed in another way (a new recovery key, linking or unlinking a provider). That once, its
  secret goes as before; so does a new password or deleting the account before the move. A new
  account is shown a recovery key once; write it down.
- **Reporting a message** (from its menu, not on your own). The dialog names who takes
  reports here and who of them is away, and you can untick anyone you would rather not
  tell, and say why. They see your name and the message as you have it; the server sees
  that you wrote to them, not what. If the message has a file, the file goes too, and the
  server can then see which conversation it came from, because it holds that same file
  there: the dialog says so, and unticking the file sends the words only. The one who wrote
  it is never told, and if they take reports themselves they are not offered. Someone away
  gets it only if you keep it on the server, sealed, until they are back: you are asked in
  the dialog, for this one report, also with your copies off, and it counts against your
  quota as a kept message does. It stays open while you are muted, timed out or may only
  read, since it is a direct message. It is closed during the wait for new members, like every direct message. From behind a
  pseudonym it goes to those online only, and they see that pseudonym. A guest reaches
  those online only. If nobody takes reports, the dialog says so and nothing is sent.
- **What came from Discord.** On a server moved from Discord, a channel with old messages
  offers them in a pane of its own, beside the conversation, labelled *Imported from Discord,
  unverified. This server can read it.* They were never encrypted, and nobody signed them:
  whoever runs the server could have changed them. Anyone signed in to an account and standing
  in the channel can read and search them, a guest not, and the server sees what you search. It is not kept, nor who opened what. Your
  device keeps none of it, and a reload forgets it. Sign in with that Discord, or link it, and
  your own posts offer *Hide* and *Delete*, one by one or all at once under *Settings → Privacy
  & data*. Hidden, only you see them, and whoever runs the server still has them; *Show* brings
  them back. Deleted, they are gone from this server, and no later import brings them back, also if
  you have left Discord by then. Copies of the database made before that still hold them until whoever
  runs the server deletes those copies: the guide asks for 30 days at most, and nothing on the server
  enforces it. If such a copy is restored, your delete goes with it. Your posts are back, a later import
  can bring more of them, and you would have to delete them again. Someone else's post that names you or
  forwards yours stays: it is theirs. A post of yours that
  opened a thread stays for the replies in it, for others with no author and no words, and named
  "Thread". Deleting your account takes them too, also after you unlinked Discord: since 1.12 the server
  keeps which Discord id you unlinked, for that alone, and your data export lists it. A moderator's
  *Hide*, your block list and *Report* do not reach these rows; removing a banned member's posts
  does, by when they were written. Only an admin deletes someone else's, and it takes a code.
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
  read your channels on another device, as far back as the channel keeps them (see
  *Limits*), and catch up on what people wrote while
  you were away; somebody online gets a direct message kept for them at once. It
  works
  in channels from the server's `channels.json` and in direct messages. Temporary
  channels, and channels that are anonymous or hide their members, keep nothing.
- **People who join later.** They read from the moment they joined, unless you choose
  otherwise: the switch *Share recent channel chat with newcomers* in Settings, which starts
  off, and is also in the copies question if you may use it here. With it on, someone who
  joins gets the keys to everything the channel still keeps of yours, not only recent chat, and can
  ask your app for recent chat, which they see as your word. With it off, they read from the
  moment they joined. It also takes the *Share history* privilege here: without it the switch
  does nothing on this server, and a guest holds no privileges, so a guest does not share. The
  switch is one setting per device, for all your servers; the privilege is per server. Turning
  it off, or losing the privilege, takes back nothing already given.
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
  it cannot make one up. While you cannot write in that conversation (a timeout in a
  channel, the wait for new members in a direct one) the bin does not offer the first,
  and says why: a tombstone is a message, so the server would refuse it after your
  rows had gone. It is back when that ends.
- **Deleting your account.** *Your account → Delete account…* asks for the name,
  the password and, with codes on, a code. The vault, the messages the account
  kept, its keys, its memberships, sessions and remembered devices go from the
  server; the name is free for someone else, and people who pinned the old
  account are told the new one is another account. What others wrote to you
  stays theirs until it expires, and so do their copies of what you wrote. A row
  of the moderation log naming the account stays until `modlog_days` are up. The
  last admin cannot delete itself: make another admin first.
- **Kept copies follow the channel's rules.** In an announcement channel only its
  managers' copies are kept, slow mode paces copies as it paces posts, and a copy
  is only kept from inside the channel.
- **Block** in a member's menu is yours alone. Their messages fold to one line that
  *Show* opens, their direct messages, pokes and invites make no sound and raise
  nothing, their conversation leaves your list, what they share of a channel's past
  is not taken, and they are silenced in your call. Everything still arrives and is
  kept, so unblocking brings it back, and a moderator's actions apply as before.
  They are not told: an invite is left unanswered rather than declined, and a
  message of theirs is delivered as usual. *Settings → Privacy & data* lists who you
  blocked on the server on screen. Your list follows your account, sealed in the
  vault, at most 200 people. As a guest it stays on this device and goes with a
  browser's site data, and a guest you block is only a name: the block falls on
  whoever uses that name next, and a guest can get past it with another. Nothing
  changes in a channel where people go by pseudonyms, since going quiet for one
  would say who it is. Someone blocked can still be heard for a moment as they join
  a call, and still lights up as speaking.
- **Verify identity** in a member's menu shows a safety number for the two of you.
  Compare it in person or on a call. If it matches, nobody stands between you,
  including the server. When somebody's identity changes, you are told — also when
  they are away, when a name you know turns up as a different account (deleted
  and taken again, say), and when an account you know shows up as a guest.
  While the conversation runs on another key than the one pinned, there is no
  number to compare: reconnect to them first.

### Display names and pictures

In the account panel you can set a display name and a picture. People see
`Robert Example @bobby`: the chosen name beside the account's, never instead of it.
A display name cannot hold an `@`, end in a `#tag`, or be (or look like) another
account's name. In an anonymous channel, or one hiding its members, people see
neither. Holders of `voipc:profiles` who hold no less than you can clear them, also while you are
away, and everyone connected is told. You can pick others.

## Signing in with Discord, Google or Facebook

Optional, and only where the relay has a web address with a certificate browsers accept, because the
provider sends the browser back there. Without one, nothing changes and no buttons show. Instagram is not
possible: its API serves professional accounts only. Facebook is there because the library has it, and is
untested.

**Setting it up.** Each relay registers its own application at each provider: no central service is
involved. The redirect address is `https://<your host:port>/account/oauth/<discord|google|facebook>/cb`.

```toml
[accounts]
public_url = "https://voice.example.org:9987"
```

```sh
VOIPC_OAUTH_DISCORD_ID=…     VOIPC_OAUTH_DISCORD_SECRET=…
VOIPC_OAUTH_GOOGLE_ID=…      VOIPC_OAUTH_GOOGLE_SECRET=…
```

**Signing in.** Account tab → *Continue with Discord*. The app shows a three-digit code and opens the
provider; back on the relay's page, the person taps that code, or *None of these* if the app shows none of them,
which ends the sign-in. Only then is the provider asked who it is. The code is against somebody sending you their
link. Only the browser the provider sent back can tap it, so they cannot tap for you. It is not perfect (they can
tell you which code to tap, or ask you for that page's address, and tapping one without looking hits the right one
time in three), which is why getting this far opens nothing yet:

**A provider says who you are. It cannot unlock your messages.** The relay sees all a provider says, so no key
may come from it. So a device that signs in this way needs one of these before it gets in at all:

- on a device already remembered, nothing: its device key signs in, and the provider is not asked;
- the **recovery key**, shown once when the account is opened;
- **another of your devices**, online: it asks whether this is you. On your yes the new device shows a six-digit
  code in its window *Check your other device*, and you type that code on the old device, which does not show it. If
  it is the code the old device worked out, it says so and hands the key over, and the new device asks whether you
  typed it there. A typo can be typed again three times; then the old device says no and warns that someone may be in
  between. A code anywhere else, in an error, a message, a notice or another dialog, is not it: a hostile server can run its own side
  of the request and show you the code for that, so say no on the old device. Approving signs that device out here,
  as any sign-in on another device does. Asking again ends an ask still open. Update the old device first: a device
  from before this change and a device after it cannot pair;
- **your password**, on an account that has one.

Someone who has only your provider account therefore joins no channel, reads nothing, and does not take your
connection over. They can ask your other device for the key, at most three times and then once per ten minutes:
say no, and change that provider's password. Those asks are the account's, so while they keep taking them your own new
device is told to try later, and an ask of theirs closes one of yours still open, with the warning that nothing was handed
over: your recovery key or password still opens it. A hostile server can ask more often, but your device takes three, then
one per ten minutes, says no to the rest and tells you, and each ask it does take needs your yes. That count lasts while the
app or page runs: a restart, a reload or another browser tab starts it over.

**The first time** (an account nobody opened) the device makes the vault and shows the recovery key. Where
sign-up is open, a provider nobody here knows gets to choose a name first; elsewhere it is told that no account
uses that sign-in. It shows the key before the account opens, so a refusal after that leaves you the key that opens
it. If the server still says nobody opened the account, that try never reached it, and the key from the device where
the account did open is the one that counts. A server can claim an account was never opened, to hide its vault and
the pins in it, so a device that remembers the account refuses, and the dialog asks you to stop if you have used it
before. A device that remembers nothing cannot tell. A server can also give the account another name, which passes
that check: the dialog then says which name this device knows you by.

### An account the move made for you

A server moved from Discord ([MOVING.md](MOVING.md)) holds an account for each of its members,
which nobody has opened. It has a name and groups, no password, and no vault. Choose *Continue
with Discord*: the name screen starts with the name you had, or with the end of your Discord id
after it if someone holds that or cleaning it took more than a dot away. You can change it this
once, and you get a recovery key. From then on it is yours, as if you had made it. Someone already here should
link Discord before the import, or their Discord lands on the new account and linking is refused.

- **A claim gives** your name, your badges and what they open: the channels your roles passed on
  Discord. The hide and delete buttons on your old posts too.
- **It does not give power.** What your role could do on Discord waits for an admin's OK, and then
  for two-factor codes on your account. With no password, you confirm with your provider first: the
  question about codes has the button. Nor does a group with privileges the account was given before
  you opened it: that waits too.
- **The wait for new members** does not hold you if you were on the Discord server for the whole
  wait when the import ran. Otherwise it counts from when you opened the account. A plain imported
  group does not lift it.
- **An account nobody opens** goes after `unclaimed_days` (90 by default), and frees its name. A
  later import makes it anew for someone still on Discord, unless an admin left them out.
- **Banned on Discord:** an account named `dc-<their Discord id>`, disabled, which only `*` sees in
  the account list, with four more characters if that name is taken. No name and no
  reason come with it, unless an account of theirs was waiting and both those names are taken. It
  covers that Discord id only: on an open server the person can come back another way.

**Linking** an existing account: account panel → *Link*, with your password (and code). You can then sign in
through the provider, and your password or recovery key still unlocks a new device. *Unlink* refuses the last way in.

**Without a password**, what would ask for one asks for your two-factor code, or, without codes, for the
provider again (*Confirm it's you* in the account panel, good for a few minutes). To add a password, use *Forgot
your password?* with the recovery key.

**Lost every device and the recovery key?** `voipc-server admin reclaim <name>` wipes the vault and identity so
that the provider's sign-in opens the account anew. What the vault held is gone: pinned identities, choices, who was
blocked and the key to the account's kept messages, and everyone who knew it is warned. Those kept messages stay on the
server until their timer, the server's retention or the channel's window takes them. The account can no longer read
them, the others they were for keep the keys they hold, and they still count against its quota. Where the move made the account, its groups with privileges wait for an admin's OK again. The last holder of `*` is
refused: give that group to another account first. Accounts with a password are refused: this would lock them out. An old device found later still remembers the old
key, and refuses a pairing with the new one as it would a hostile server's: unlock it with the new recovery key, or
forget the device there first.

**A provider sign-in never replaces an identity**, not even with a two-factor code. Signing in with the password
is what can.

## What the server learns

From accounts:

- account names
- your display name and profile picture, which it can read and hands to anyone who
  asks, guests too. It also sees whose picture each person fetches
- for a linked provider, the provider's id for you and the name it gives. Never your email, and no provider
  token is kept
- for each password, the public half of the key derived from it (since 1.12; an account
  that has not given its password to a 1.12 app yet keeps an Argon2id hash of a secret
  derived from it)
- the Discord ids an account unlinked, kept only so that deleting it takes their posts too
- identity public keys
- the public keys of remembered devices
- two-factor secrets, sealed by the key file
- groups, what they hand out, and which groups each gated channel names
- sign-in records with hashed IP addresses
- each account's vault, which it cannot open without guessing the password: each
  guess costs 600,000 PBKDF2-SHA256 rounds, so a long password used nowhere else
  is what protects it. Each item's name, write times and size are plain: it can see
  that a list of blocked people (`item.blocks`) exists and changed, and how long it
  is to the nearest kilobyte, never who is on it. The identities you pinned are items
  too (`pins.0` and on, listed in `item.pins`), each sealed the same way and up to 48 KiB,
  so it can see about how many people you have met, and when you met more
- bans: a keyed hash of each banned address (never the address), and banned
  accounts
- that a connection asked who takes reports, and when. A report itself is a direct message:
  it learns what it learns of any, so an ask followed by a burst of messages to the staff
  says a report went. Never the text or the reason, and there is no row of a report anywhere.
  Nor the writer or the channel, unless the report carries the message's file, which it does
  until you untick it in the dialog: that same file is then listed under this conversation
  and the one it came from, so the server can see which that was, and who posted it there
- for an account the move from Discord made: that person's Discord id, when they joined that
  server, the name they had, and whether they have come. For someone banned there, their Discord
  id, in the name of a disabled account
- the Discord ids it remembers not to import, with no name beside them
- the moderation log: who did what to whom and why, by name, for `modlog_days`, also
  after those accounts are deleted. Whose posts were removed goes out to everyone who
  connects for that long, guests too, by account where it has one and by name, with who
  did it and the time span, never the channel or the reason

From kept messages:

- who wrote in which channel or direct conversation, when, and how long each message is
- each kept message's destruction timer, so it can delete the copy on time (for a
  direct message, the timer you chose)
- which channels each account keeps

From a Discord import:

- the old messages, in the clear: text, names, Discord ids, reactions, pins and the names of files.
  A row of someone anonymised as a former member has no name or id, though its text still says what
  it says. Rows stay until someone removes them, or `archive_days` if it is set
- who opens which archive and what they search for, at that moment. It keeps neither
- whose hide or delete of their posts stands, with their Discord id, so that a re-run obeys it. A wish
  has no end date, and an admin's app can read them all, as a run does to keep such posts out if
  their author has left Discord by then

Of everything but that import, it never learns the text or a key. The README under *Data Transparency* has the short
version of this list, and what a server holds without accounts.

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
  device that saw a newer copy before warns and does not save over it, and until
  its list of pinned identities is in, no key is checked or handed out;
- **withhold or replay kept copies**, but not forge or alter one: each is signed
  by its writer;
- **guess your password offline**, at the cost above;
- **decide who is a member** of a channel's log: a member it made up gets keys
  only with the notice above, and that notice is shown on the device that hands
  the key over;
- **keep a writer on an older key of their own** that still reaches somebody who
  left, which helps it only together with that person;
- **hold a copy for later**: kept copies use X25519 for their keys, not a post-quantum
  one, so a database copied today could be read by a quantum computer later;
- **show display names, pictures and a server name as it likes**: they are its word,
  so they are no proof of who someone is. That is why your app always shows the
  `@name` and the address beside them. Pictures are sanitized on your device first;
- **say who takes reports**: it can name itself, which you see before anything goes and the
  pins check, or say nobody does. On a report that reaches someone live, the reporter's name
  is its word, as on any direct message, unless that moderator has met them. A kept one is
  signed;
- **hand out `@everyone`**: it says who may use it, and the text is hidden from it,
  so it can make your app ring for a named member's message, not write that message;
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
- A channel keeps messages for up to `kept_seats` accounts, 5000 by default. Half of them
  take a seat by following it; the rest by asking, or by writing there.
- Your device remembers the identity of about 32,000 people it met, in pages kept
  outside what a sign-in sends. Those met only in open channels stop at half of that,
  and past it they are new again at each connect. Nobody is ever forgotten to make room.
  A new one goes out within five minutes and when you sign out, so a crash can make
  those few new again; a changed key, or someone you verified, goes at once.
- A copy in a channel goes for good once 10,000 newer messages have stood there for three
  days, and have three days left to run: a flood cleaned up in time, or on a short timer, takes
  nothing. A server can set a smaller window (`kept_window`). Direct conversations have no
  such limit.
- A device fetches the newest 400 keys handed to it in a direct conversation. Past those,
  older copies there can no longer be opened on a new device. In a channel a device
  fetches what opens the messages it reads, however many people came and went.
- What a channel kept that you hold no key to is not sent to you, and one quiet line in
  the chat says so: *Some earlier messages here can't be opened: they were written before
  you joined, or before many people left.* If the channel no longer keeps what this device
  had not read yet, the line says how many it does keep.
- A member a writer's app cannot reach, with no log key published or none it can trust, stops
  nobody: that writer's messages go on being kept, without a key for them. They are not named
  to the writer, those messages are sent to them all the same and counted in that line, and
  a key that comes later opens that writer's messages from their next new key at the latest.
- `retention_days` caps how long a copy stays. A message's own timer can only make
  that shorter.

## Not in this version

- Files from a Discord server: their names come, not the files. New posts into an imported
  thread: old threads are read-only in the pane. Report and hide on imported rows.
- A shared queue of reports. They are direct messages to each moderator, because someone
  outside a gated staff channel can neither post in it nor be handed its keys, and an open
  one would show every report to its members.
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
