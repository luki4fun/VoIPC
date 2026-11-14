# Moving a Discord server here

This copies a Discord server to a relay of yours: its channels and categories, roles, members, bans, emotes and
old messages. People then sign in with their Discord account and find their name and groups waiting.

It is one-way. Nothing goes back to Discord, and nothing on Discord changes, apart from one post you may ask for at
the end. Old messages come over readable: they were never encrypted, so this server can read them, and the app labels
them so. Everything written here afterwards is end-to-end encrypted as usual.

The importer is in the desktop app, because reading a Discord server takes a bot token and a browser page would hand
that token to whatever served it. The browser and Android show the dashboard, the OK list and Undo, with a card saying
why the rest is on the desktop.

## Before you start

- **Accounts on,** with `cloud = true` ([ACCOUNTS.md](ACCOUNTS.md)): the old messages live in the same database, and a
  run with messages on is refused on `cloud = false`.
- **An account holding `*`, with two-factor codes on.** Each run and each undo takes a code.
- **A web address and a certificate browsers accept** (below). Without them nobody could sign in with Discord, and
  the wizard refuses to run.
- **Disk.** The dry-run gives an estimate, and the database holds every message that comes. A message costs about
  108 bytes plus its text on SQLite, and 189 bytes plus its text on Postgres:

  | Messages | SQLite | Postgres | One SQLite copy, plain / zstd | 7 plain copies, a sum |
  |---|---|---|---|---|
  | 1 M | 0.18 GB | 0.26 GB | 0.17 / 0.07 GB | 1.2 GB |
  | 5 M | 0.85 GB | 1.24 GB | 0.84 / 0.32 GB | 5.9 GB |
  | 20 M | 3.5 GB | 5 GB | 3.4 / 1.3 GB | 24 GB |
  | 100 M | 18 GB | 26 GB | 17 / 6.5 GB | 119 GB |

  The backups are what fills a small disk. See [OPERATING.md](OPERATING.md) §7.
- **A copy of the database.** On SQLite the relay makes one itself when a run begins, beside the database, named
  `<database>.before-import-<run>`. A run resumed after its copy was dropped gets a new one,
  `<database>.before-resuming-import-<run>`, holding what that run had done before it stopped. A new run drops all but
  the last two, and nothing else on the relay removes them:
  they stay until you delete them, and they hold everything, so treat them like the database. Postgres has nothing to
  make one from here: run `pg_dump` yourself, and tick that you did.
- **`signups_per_hour`, if you expect newcomers.** People who already have an imported account do not count towards it.
- **Encrypted storage for the database.** See [Data protection](#data-protection).

The relay reads no Discord data of its own, and the token never reaches it. What it is told is what becomes the
server's own: names and topics of channels and categories; roles with their colours, order and what each could do; each
member's names, Discord id, join date and roles; the Discord ids of those banned there; emotes and stickers; and the
labelled old messages.

## The Discord application

In this order. The intents have to be on before the bot is invited.

1. At <https://discord.com/developers/applications>: **New Application**.
2. **Bot** tab:
   - **Reset Token**, and copy it once.
   - Turn off **Public Bot**.
   - Turn **on** **Server Members Intent** and **Message Content Intent**. Without them the member list and every
     message's text come back empty, with no error. The dry-run stops on what it finds, and a run that meets it later
     stops too (below).
   - A server that demands two-factor authentication of its moderators needs it on your own Discord account first.
3. **OAuth2** tab: copy the Client ID and Secret, and add the redirect `https://<host:port>/account/oauth/discord/cb`.
   The same application does both jobs: the sign-in and the reading.
4. Invite the bot with the link the wizard shows (`scope=bot&permissions=8`). It asks for Administrator because from
   2026-11-16 Discord leaves channels the bot cannot view out of the channel list, and nothing tells you which. It
   only reads, apart from the one post you may ask for.

**Over 10,000 people who can see the app.** Since 2026-06-10, Discord's docs say: "If your app has fewer than 10,000
users, you can continue accessing Privileged Intents by toggling them on", counted as "unique users who can see your
app across all the servers it's in". At the threshold: "You will have 90 days from the date of the notification to
apply", and "While in review ... your app will continue to function with the intents". "If your app is over the
10,000 user threshold and the toggle is locked, you need to apply." So turn both on before inviting the bot, and if
you are told to apply, apply. Whether a move gets approved is not known.

## The address and the certificate

```toml
[accounts]
public_url = "https://voice.example.org:9987"
```

```sh
VOIPC_OAUTH_DISCORD_ID=…     VOIPC_OAUTH_DISCORD_SECRET=…
```

Discord sends a member's browser back to that address, so it needs a certificate browsers accept on that port
([OPERATING.md](OPERATING.md) §4 and §6), and a restart at renewal.

## Tell your members first

Then, or as your first post, something like this:

```
We are moving to VoIPC, on a server run by {who}: {address}. When: {date}.

What is copied from Discord: {channels}, with messages back to {date}. Everyone's names, Discord ids, join dates and
roles, and what each role could do. The Discord ids of people banned there. Reactions, pins and the names of
attachments. Not direct messages. Not the files themselves.

Who can read it: anyone who may enter that channel on the new server, and whoever runs the server. Unlike new
messages there, which are end-to-end encrypted, these copies can be read by the server. They are marked as imported.
They are not verified, and they could be changed by whoever runs the server.

How long: {until someone removes them / {n} days}.

Your choices: sign in with Discord and you can hide or delete your own posts, one by one or all. If you do not want
an account, or your posts copied at all, tell {contact} before {date}, or any time after: your posts can be deleted by
your Discord id. Someone else's post that names you or forwards yours is theirs, and stays.

Who is responsible: {name, contact}. {Your legal basis, if you need to state one.}
```

**Someone who asked to stay out before the first run:** the wizard's third step has a box for Discord ids, one to a
line. Each gets no account, and none of their posts come. Another person's forward of them can (see
[Data protection](#data-protection)). Each takes a code, which holds ten minutes. If a code or the connection fails part way, the ids not yet sent go back in the box, and the screen says how many.

**Someone who already has an account here** should link Discord to it before the import (*Your account*). They then
get their groups and their posts with the account they have. If they did not, their Discord sign-in lands on the
account the move made, and linking is refused. On *Still to sign in*, press **Hold for now** on that row: the account
it made goes and their posts stay. They link, you press **Let back in** under *Left out*, and the next run gives them
their groups.

**Names.** Everyone the move knows now holds a name here, so a guest's name or someone's display name is refused more
often than before. Those names come free again when the account goes unopened (below).

## Running it

*Server admin → Discord move*, on the desktop.

1. **Token and server.** The token goes to discord.com only and stays in memory: not in the settings, not in a log,
   and never to the relay. It is gone when you press Done or leave the wizard, when you disconnect from the server or a
   reconnect gives up, after an hour with nothing going, and when the app quits. A network cut keeps it, so a run can go
   on. Cancel while it is being checked holds nothing.
2. **The dry-run.** It reads and counts, and writes nothing anywhere. It can take a few minutes, and it names what
   will not fit. Nothing it warns of stops a run but the things it says do.
3. **What comes.** Channels and categories, roles, channel permissions, members and their roles, bans, emotes and
   stickers, messages, threads, pins, reactions, and whether to anonymise those who have left (that one starts on every
   time). Messages need channels;
   threads, pins and reactions need messages; permissions need channels. Each channel can be left out, or have its
   messages off. Then the tick for what copying messages means:

   > This copies your members' messages out of Discord to this server, which can read them. Discord's Terms forbid "scraping our services without our written consent", and its Developer Policy has a rule against mining or scraping; read the current policy. Discord may act against your bot or your account. Members' messages are their personal data: you answer for telling them and for the law where you are. This is not legal advice.
4. **The run,** after a code. On SQLite the copy of the database comes first, and its path is shown. Discord's rate
   decides how long this takes: the dry-run gives an estimate, and it can be many hours. The app has to stay open and
   connected. **Stop** loses nothing, and lets an emote it has in hand finish first.
5. **The end screen** lists everything, including what was left out. That list stays on this screen only. The report
   kept on the relay holds counts and notes about what came, and names nothing left out.

**After a stop,** *Go on* keeps your choices and asks for the tick and a code again. *Done* forgets the token. Past an
hour with nothing going it starts over from the token, so the dry-run and your ticks come again too. So does *Done* or an
app restart, and a new dry-run
cannot tell a channel you turned off from one the run had not reached, or one you left out from one it never got to.
Each row and a warning say so, so tick the ones you want. If the last run made no channels, as with Channels off,
nothing shows as left out.

**After a network cut,** the wizard stays where it was, and a step that was waiting says the connection went. At the choices, your ticks are all
still there. Waiting on the code, it goes back to the choices. A run lands on its end screen, whose notes are the only
copy, with *Go on*. Each new connection asks for a code again, and **an account has five tries in fifteen minutes, right
or wrong**, so someone whose connection keeps dropping during a move can meet "Too many attempts. Wait a few minutes."
A code holds ten minutes on a connection, so a steady run does not. **Past five minutes without a connection** the app
gives up, and the wizard, its ticks, the end screen's notes and the token go. What the run stored is safe on the relay:
connect, enter the token, and make a new dry-run, whose warning covers the channels the run had not reached.

**A run can stop itself on what Discord sends.** If a channel's first page comes back with blank messages, the run stops
with "#name: Discord is sending blank messages: Message Content is off." Under 20 rows on that page it asks Discord
about Message Content first and goes on if it is on, and a Rich Presence invite or a post with its embeds suppressed
counts neither way, so one such post does not stop it. With Anonymise on, a member list that will not come, or comes
back empty, stops the run too, because everyone would go in as a former member for good.

Nothing about a run stays on your machine: messages pass through memory, and no file holds them.

### Private channels

A channel is private here if @everyone cannot view it or cannot read its history on Discord, or if a role is denied
viewing it. Each one's messages stay on Discord until you tick it on that run, because on the relay they sit in a table
the server can read. **Its name and topic go regardless; Leave out to keep them off.**

**One closed on Discord after a run** came open here, and a later run leaves its gate as it is. While that gate is open,
the relay refuses the channel: "Private on Discord now and open here. Give it a gate, then run again." Nothing of it is
walked, the end screen names it, and it is refused again each run until you give it a gate or it opens on Discord again.
A gate set by hand goes on as before, and new messages come in behind it if you tick it. From then on it counts as
private: only `*` opens that gate, and while it stands open no run files there. A gate holding `user` counts as open.
One where only reading the history was closed has no gate to go by, so on a later run its messages start off, saying
why, and stay off unless you tick it: a tick files them where everyone in that channel can read them. Every run and every *Go on* reads Discord's channels and roles again
first, so all of this goes by what Discord says when the run starts, not by the dry-run. **A channel closed during a run
is not noticed until the next one.**

While a private channel holds imported messages, someone without `*` may only narrow its gate, never open it: a gate
holding `user` would hand its history to every account. Anyone who may grant a group that passes the gate can still
add a person to it. **Deleting a channel that holds imported messages takes `*` and a code.** Its archive goes with it,
and no later run brings it back. With `voipc:channels` you may delete one that holds none.

Private threads never move: only the people added to one could read it, and nothing here can say who they were.

A forum becomes a text channel, its posts threads you read in the archive pane.

### Who holds what afterwards

The dashboard says "412 of 1,530 signed in".

- **A role's plain groups** come with their badge, colour and order, and hold no privileges. They do not lift the wait
  for new members.
- **What a role could do on Discord waits for your OK.** Each role with permissions gets a second group, named
  `<role>-power`, with the matching privileges, and nobody holds it until you press **OK** on *Waiting for your OK*,
  with a code. That list greys out anyone who has not signed in yet, and a row can only be answered once they have.
  Whoever you OK can give that group to others, so check with them outside Discord first: a stolen Discord account
  signs in like the real one. What you answer no to comes back next run, as long as they still hold that role there.
  A group with privileges given by hand waits the same way, if the account was not opened when it came to hold them, or
  after `admin reclaim`.
- **Two-factor codes:** a privilege takes effect once its holder has codes on, and the app asks them. Someone with no
  password, back on a remembered device, confirms with their provider first: the question has the button.
- **An account nobody opens** goes after `unclaimed_days` (90 by default, 0 is never), and its name with it.
- **Someone who joins during a run,** with Anonymise on, goes in under their name, though the member list was read
  before they came: the app asks Discord once about anyone who wrote since then and is not on it. Their account comes
  with the next run. If Discord will not say, their posts go in as a former member's for good, and the end screen says so
  without naming them.
- **Banned on Discord:** a disabled account named `dc-<their id>`, on the Users tab's *Banned* filter, for `*` alone,
  and on no other list, with no name and no reason kept. If someone holds that name, four more characters nobody can guess are added. An unopened
  account banned since takes that name too, unless both are taken: then it keeps its own, and the end screen says so.
  Undoing the run that did this drops the account, and the next import makes it again. A banned account does not expire
  and cannot be signed in to. That covers that Discord id only: on an open server the person can come back another way.
  The Bans tab holds your own bans, not these. The end screen says who is no longer banned there. **Lift ban** on their
  row ends it here, with a code: they can come in the way anyone new can, and what they wrote stays. They move to *Left
  out* as held, so no later import bans them again or makes them an account. *Let back in* there undoes that, and the
  next import bans them again if Discord still does. Someone who deleted their account themselves stays left out, and
  their posts gone; since 1.12 a lift holds for them as well (before, the next import banned them again).
- **Someone who signed in and is banned on Discord too** keeps their account: an import never suspends anyone who has
  opened one, nor links Discord back to someone who took it off, undo or no undo. Ban them by name if you mean it.
  Someone who deleted their account here and is banned on Discord gets the disabled row.

**To leave someone out later:** *Leave out and delete their posts* on their row, or **Delete by Discord id** for someone
who writes in from outside. **Hold for now** drops a waiting account and keeps their posts coming.

### The move post

The one thing the importer ever writes to Discord, and only when you press Post. The wizard offers a text saying where
to go, what happened to the messages if any came, and that names and groups are waiting if members came. You choose
whether to reach `@everyone`, and it goes to a channel everyone there can read, never a private one. It can add a new
join link for newcomers, without touching what you wrote.

## What members see

Their first sign-in is *Continue with Discord*. The name screen starts with the name they had, as far as names here
allow. A dot becomes `_`, and `a.b` and `a_b` are then one name, which whoever the import reaches first holds. If
cleaning took anything else away, or someone holds the name, the end of their Discord id follows it, so `_alice` never
takes `alice`. It cannot be changed later, and they get a recovery key. Their badges and gates are there at once.

Their app follows the moved text channels they may see from the first connect, with no click and nobody told: an
ordinary post shows as a dot on the row, a mention as a count and a sound, and they can leave any channel. A channel they
pass only by holding `*` is not followed, and a click enters it. *Server admin → Channels* turns following off per channel,
and a later run leaves that as it is.

A channel with old messages offers them in a pane of their own, beside the conversation and never in it: labelled
"Imported from Discord, unverified. This server can read it.", with its own search, threads, and pins. Someone who
signed in with that Discord can hide or delete their own posts there, or all of them at once under *Settings → Privacy
& data*. A thread whose opening post was hidden or deleted stays for the replies in it, showing others a row with no
author, no text and the name "Thread". A name written inside a message cannot change how the row is drawn, so a search for a name
holding `*` or `[` finds that person's own posts and not where others mentioned them. [ACCOUNTS.md](ACCOUNTS.md) has it
all, and tells members what the server holds.

## Data protection

**Notes, not legal advice. Ask someone qualified where you live.**

- Under the GDPR and similar law, you become responsible for what you copy.
- Messages and names are personal data, and some communities' are sensitive.
- You need a legal basis, and you need to tell people, as above.
- A member who has signed in erases their own. For someone else, delete by Discord id on request. An anonymised row has
  no id to find it by: search for it and delete that message.
- "Anonymise ex-members" removes the name and id, not what the text says, so it may not be anonymous in law.
- Deleting someone's posts takes what they wrote, not what others wrote about them. Another person's post keeps the name
  it mentioned them by, and a forward keeps their words, also for someone who asked to stay out before the first run: it
  came as the forwarder's post. No later run changes these. If they ask, an admin can search for the name and delete
  those messages, with a code. Someone left out, or whose account is deleted, reads `@unknown` only in messages a run
  brings after that.
- Decide `archive_days`, and say what you decided. It is 0 by default, kept until removed. Backups hold what was deleted
  until they are deleted. That is 30 days at most if you follow [OPERATING.md](OPERATING.md) §7 and run its timer; nothing
  on the relay ages a run's copy out.
- The database and its copies now hold readable messages: guard shell access as you would the messages themselves.
- Think about where the server stands and who hosts it.

**Discord's own rules.** Its Terms (read on 2026-11-04, effective 2025-09-29) forbid "scraping our services without
our written consent, including by using any robot, spider, crawler, scraper, or other automatic device, process, or
software". Its Developer Policy has a rule against mining or scraping. Neither says whether a server owner moving their
own community counts. The published 2022 text of the Developer Terms asks you to delete API data when a user asks,
which *Delete* and delete by Discord id answer, and for "encryption of the data at rest", so **put the database and its
copies on an encrypted disk**.

**Nobody writing this could read the current Developer Policy or Developer Terms: those pages refused automated
reads.** Read them yourself: <https://discord.com/developers/docs/policies-and-agreements/developer-policy>. The
consequence could fall on your application or your account.

## What does not move

- direct messages (a bot cannot read them)
- files: names only, and the record only helps while the Discord server exists
- voice history
- the history of edits, and any edit or deletion after a run reached that message
- full embeds next to text
- forum tags
- who reacted: only how many
- private threads, and threads you can continue: old ones are read-only in the pane
- scheduled events, polls beyond the question, soundboard, automod, bots and webhooks
- permission rules for one person, and deny rules: the report lists them

Permissions come over as gates, which say who may and never who may not, so a channel can come out narrower than it
was: one role denied on Discord closes it here to people with no role at all. The dry-run lists each one. Check those
gates after the run.

## Undo and re-runs

**A later run** takes new messages only. It reads the channels you had, and turns on a channel made on Discord since,
unless it is private. It remembers what the ledger shows and nothing else: a channel no run made starts left out, and
one whose messages never came starts off. **A channel that came before starts on again unless you leave it out
each time**, because a later run's choices are stored nowhere. A private one starts off and takes its tick again each
run: how far it was read is the relay's word, and that must not stand in for yours. What you renamed or changed here stays yours, and a
channel, category, emote or group you deleted here stays deleted, a group being named on the end screen as not having
come. Undoing the run that made it clears that. A group's name stays; its badge, colour and order follow Discord. To
start over, undo and run again. A message deleted on Discord after a run stays here until you delete it.

**Undo,** on a run, shows what goes first and takes a code. A later run has to be undone first. It removes the
channels, categories and emotes that run made, everything written in those channels, the accounts nobody opened and the
groups, then asks the worker to clear the old messages, and a new run says "Still clearing the last undo." until that
is done, usually seconds. If you leave halfway, the run says so, and Undo goes on from there. Accounts someone opened
stay, and lose the groups that run made. A later run's changes to who holds an earlier run's groups stay, so someone it
added to a group keeps it, and someone it took out stays out: check your gates afterwards. A group a gate elsewhere
still names stays too, and the next run takes it up. A cut in the moment between adding an emote and recording it,
followed by a new dry-run rather than *Go on*, leaves that emote here with a second beside it as `name_2`, and Undo takes
only the second.

**What a person deleted stays deleted** through a later run, and through an undo and a new run: the relay remembers the
wish, not the message. That holds for someone who has since left Discord, whose rows would come with no name for the
relay to match: with Anonymise on, a run first reads the list of wishes, by Discord id, keeps it in memory, and drops
those rows. A hide holds the same way. A thread's title goes with its owner's wish, leaving the neutral row above; for a
thread opened on another person's message, only a delete reaches the title, and at the next run rather than at once. Two
gaps remain. A thread opened on Discord after the message under it was deleted here files its title under the thread's
owner, though it may quote the deleted words; the owner's own delete reaches it. And in a new run after an undo, threads
come first, so a title stands until the walk reaches its first message, and a run stopped in that gap leaves it readable
until *Go on*.

**Backups:** the copies named above, and your own. A copy made before someone's deletion still holds their posts until
you delete it. The relay does not age its own out: each stays until a new run pushes it past the last two.

**Restoring a copy forgets every wish made since,** whether the relay's copy or your own. The wishes live in the same
database. So what people deleted since is back at once, the next run files the rest again, and accounts they deleted are
back too. *What a person deleted stays deleted* holds only without a restore. To start over, use Undo, which keeps the
wishes. If you have to restore, keep the database you are replacing: its tables `voipc_archive_wishes` and
`voipc_import_excluded` are the only record of who asked for what. Delete those posts again, and tell those people.

## When you are done

After the last run, not between: *Go on* needs the bot and its token.

1. Remove the bot, on Discord: Server Settings, Integrations, the app, Kick.
2. In the Developer Portal: Bot, Reset Token, and do not keep the new one. A later run needs it back, with the invite
   link the wizard shows.
3. Keep or close the Discord server. Attachments are named in the archive, not copied, so they go with it.
4. Delete the relay's copies of the database (`<database>.before-import-<run>`, beside it), or your own dumps, when you
   know the move went well. Each holds everything, also posts members have deleted since. Nothing on the relay ages them
   out, though the timer in [OPERATING.md](OPERATING.md) §7 does at 30 days.
5. The reminder on the dashboard stays until you tick it, on that device.
