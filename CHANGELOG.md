# Changelog

All notable changes to VoIPC are documented here.

## [0.9.1] - 2026-09-18

Protocol version 9, unchanged: a 0.9.1 client and a 0.9.0 server still talk to
each other, so a server can be updated whenever it suits. Everything here is the
channel sidebar and the chat pane.

### Fixed

- **One look at a channel you were not in stopped every text channel from
  opening.** Clicking a voice channel, or a text channel you had not joined,
  left a preview up — and a preview outranks the text channel whose chat is
  open, so from then on clicking a channel you *were* in set the state and
  changed nothing on screen. The only way out was clicking the voice channel you
  were standing in, which is the one thing that dropped the preview. Asking for
  a channel's chat now drops the preview along with it, which fixes the same
  wedge in both layouts and on every path into it

### Changed — joining works without a double click

A double click was the only way into a voice channel, and a phone has no double
click: on a touch screen the second tap is eaten as a zoom gesture more often
than not, and nothing on screen ever said what to do instead.

- **The chat pane offers the way in**, the way it already did for text channels:
  click a channel to look at it and a **Join** button sits under its chat, for
  voice channels as well as text ones, password-protected ones included — the
  password prompt opens from the same button. A double click on a voice row
  still joins it, for the hands that have always done it that way
- **A click on a channel opens its chat in both layouts.** The classic sidebar
  previewed a voice channel without bringing the chat forward, so on a phone —
  where the channel list is a tab covering everything else — tapping a voice
  channel looked like it did nothing at all

## [0.9.0] - 2026-09-17

**Protocol 8 → 9.** A client and a server must match exactly, so both have to be
updated together.

### Added — text channels

A voice channel is somewhere you stand, and you can only stand in one place.
That has been true since the first release and it stays true. It was also the
only kind of channel there was, which meant chat lived wherever your voice did:
to read a conversation you had to move your microphone into it.

- **Text channels** are a subscription rather than a move. Join as many as you
  like, read and write in them while sitting in whatever voice channel you are
  in, and leave one from the ✕ on its row. Voice is unchanged: still one channel
  at a time, still the same join, still the same leave
- **A server can put everyone in one on connect.** A channel in `channels.json`
  with `"text": true, "auto_join": true` is joined by every client as it
  arrives — the `#general` a new server wants people to land in. Leave it and it
  stays left: the client remembers that per server and does not re-join on the
  next connection, which is also why the server itself joins nobody. Without
  `auto_join` a text channel is there to be joined by hand
- **Anyone can create one**, from the same + button as a voice channel, now with
  a Voice/Text choice. Like any user-created channel it goes away once the last
  member leaves and the empty-channel timeout passes
- **Joining a voice channel no longer moves the chat pane.** It shows whatever
  you last opened until you ask for something else, which is the modern habit;
  clicking the voice channel you are already in is how you ask for its chat
- Messages are end-to-end encrypted exactly as channel chat already was, one
  sender-key group per channel, and the server still stores no history: a
  newcomer asks the members who offer it, as below

### Added — chat you can keep, and delete, on purpose

Voice and screen share are solved by not persisting: nothing is stored, so
nothing leaks. Text cannot work that way — a conversation nobody can scroll back
through is a worse conversation — but it should not turn the app into an archive
either. So persistence stays opt-in, and the parts of it that were quietly
broken or missing are now finished.

- **You can see who shares.** A member who answers requests for recent chat is
  marked in the member list, so it is visible whether a channel has anyone to
  ask, and who. It is one flag per person, the same shape as mute and deafen,
  and the only thing about chat the server is told — it has always seen the
  requests themselves go past
- **History is merged, not taken from one person.** Different people hold
  different parts of a conversation: whoever was away has the older half,
  whoever just arrived has only the newest. A newcomer now asks up to three
  members who share, and what comes back is folded together in order, without
  duplicates. Each hand-off leaves its own divider, so it is clear which part
  came from whom
- **A message carries an id, inside the encryption.** Minted by its sender and
  never seen by the server, so two people's copies of the same message are
  recognised as one. Chat stored before this release has no id and is still
  deduplicated the old way — same author, same text, close in time
- **Deleting is permanent, and undoable on purpose.** Clearing a channel records
  what was there, and nothing older is ever merged back in. So a channel you
  cleared stays cleared, however many members re-offer it and however often you
  reconnect. If you deleted it by accident, the history button in the chat
  header asks the sharers again and takes the deletion back — a thing you do,
  not a thing that happens to you
- **Chat history is filed per server.** Two servers' `#general` are two rooms,
  and they no longer share one bucket. This closes a hole that `auto_join` would
  otherwise have opened: a server could publish a text channel called `general`,
  have every client join it on connect, and ask for "the history of #general" —
  and be handed what its user had written somewhere else entirely. History from
  before this release is adopted by the first server you connect to
- **A direct message is filed under the person, not their number.** Every
  conversation was kept under the two user ids — and a user id is handed out
  afresh on every connection and passed on as people come and go, so yesterday's
  conversation with one person was shown as today's with whoever holds that pair
  of numbers now, on any server. They are filed by server and name from here on.
  The conversations stored the old way name nobody in particular, so they are
  not carried over; a name is not proof of who somebody is either, which is why
  accounts are the next thing on the list. The list of open conversations in the
  sidebar now belongs to the connection, for the same reason the ids do —
  opening a direct message with somebody brings back what you wrote to them
  before
- **Messages can be given a destruction timer.** Off everywhere unless somebody
  turns it on. A channel's creator or an admin sets one from the gear icon —
  five minutes to seven days — and every message written there from then on is
  deleted by every client when its time is up. A direct message has no channel
  to take that from, so the clock in the chat header is your own: it travels
  with the messages you send, and the other side deletes them when it runs out.
  The timer rides inside the encryption next to the message, where the relay can
  neither read it nor change it, and the moment is worked out from the message's
  own timestamp, so every copy of it goes at once rather than a few minutes
  apart. What a member re-sharing a conversation says about a message is only
  the outer bound: the channel's timer applies to what they hand over as well,
  including to a message they strip it from, and a copy of something already
  here can bring its deletion forward but never push it back. It is a rule about
  the app and not about people — somebody who was there can still keep their own
  copy of what they read
- **How much is kept is yours to set.** The archive keeps a thousand
  conversations — channels and people together, across every server — and the
  oldest beyond that are dropped when chat is next saved. Settings → Data has
  the number, and 0 keeps all of them: what it bounds is how much is written out
  at once, not how far back any one conversation goes, which is five hundred
  messages either way
- **Fixed: the encrypted chat vault could not be reloaded.** It has stored
  messages in a format it could not read back since 0.4.0, so unlocking an
  archive that held any message failed. The format is now v2, and a v1 file is
  read where it still can be — which is every archive that never stored a
  shared-history divider; the others were never loadable by any build

### Fixed — end-to-end encryption

Text channels mean a client holds several channels' keys at once. Everything
below was written for one, and this release is where that assumption is made
good. Two of these are older than text channels and got worse with them.

- **A message is now bound to the channel it was sent in.** The channel id
  inside the ciphertext is checked against the one the server names, rather than
  being taken on trust. Without it a relay could re-label a message from one
  channel as another, and it would be shown, stored, and later shared under the
  wrong channel's name. The same check applies to sender keys, so a member of
  one channel cannot install a key for another. Clients also drop a message for
  a channel they are not in at all
- **Sender keys are rotated when somebody leaves.** The chain key a departing
  member holds used to keep working forever, so a former member of a channel
  could go on reading it. Now the next message sent after anyone leaves starts a
  fresh chain, handed to the members still there. It costs nothing until
  somebody writes, and nothing at all for people who only read. Leaving the
  channel yourself, or re-joining it, forgets the chain rather than cancelling
  the rotation that was due — and a two-person channel, where the one member
  who held your key is the one who left, rotates like any other instead of
  quietly keeping the key they walked out with
- **Media keys are rotated when somebody leaves, too.** Voice, video and screen
  audio share one key per channel, and it used to be minted once and never
  again: a member who left, or was kicked, kept a working key for as long as the
  channel lasted. Now the lowest remaining user id mints the next generation and
  hands it to the others over the sessions it already has — nobody is elected by
  the server, and two members who disagree about the roster for a moment
  converge on the same key rather than going deaf to each other. The previous
  generation stays usable for a moment so the rotation is not an audible gap,
  which is also the only window the member who left can still read
- **A speaker's nonce no longer comes from the server.** Media packets were
  numbered with the session id the server hands out. Two members of a channel
  encrypt under the same key, so a server that gave two of them the same session
  id got the same key and nonce twice — and the XOR of two people talking.
  Each client now picks four random bytes for itself when it joins and carries
  them in the packet header, which is what the README always claimed the nonce
  did
- **A media key is taken only from a member of the channel it is for.** Sender
  keys were checked this way and media keys were not, which is the wrong way
  round: a sender key decides what one person can read, a media key is the key
  the microphone encrypts under. Anyone able to open a pairwise session with a
  client — which is anyone on the server — could hand it a key for the room it
  was standing in, and a relay willing to carry that could then listen to
  everything said in there. The key is now refused before it is opened unless
  the roster puts its sender in the channel, and it is refused again if the
  channel named inside it is not the room we are in — believing that would
  otherwise take away sending, receiving and passing the key on, all at once,
  with nothing on screen to say why
- **Key generations wrap instead of running out.** They are numbered with two
  bytes, and the last number was treated as the last generation there could be:
  a member on their way out could send it and every rotation after that would
  be refused, freezing the channel on the key they were walking away with —
  which is the one case rotation exists for
- **A shared history is accepted only from a member of that channel**, like the
  keys. It arrives over a pairwise session, so it never needed the channel's
  group key; a stranger with a colluding relay could hand a client a
  conversation of their invention, which it would file, show and pass on
- **Leaving a voice channel no longer resets the pairwise session with the
  person who left.** It made sense when the only place you shared with somebody
  was the channel you stood in. Now they may be in three text channels with
  you, and dropping the session meant the next thing they did anywhere started
  a second key agreement with them — two sessions for one person, which shows
  up as one message that cannot be read and then one that quietly decrypts
  "with the previous session state" — while their sender key was not handed
  over next door because we believed there was no session to hand it over
- **A text channel cannot be anonymous.** Pseudonyms hide a member who is
  nowhere else, and a text channel is one you are in *besides* the voice channel
  you stand in — where the same user id carries your real name. The server
  refuses the combination at creation, in `channels.json` and at runtime rather
  than offering privacy it cannot deliver. Anonymous voice channels are
  unchanged
- **A text channel's member list no longer names the voice room its members are
  standing in.** Each roster now describes the channel it is a roster of
- **A member who was already in a text channel could not be read at all.** Their
  messages, and the channel's history, arrived as "decryption failed" until one
  side left and re-joined. Three things caused it together, and each is fixed
  where it was: a client recorded having handed its sender key to peers the
  server had dropped it for — it hands one to every peer it opens a session
  with, wherever they are, and the server relays only between two members — so
  it then skipped the person who had actually never received it; nobody was
  responsible for handing a key *to* a newcomer, because a text channel does not
  move anybody and the member therefore learns of the join from a broadcast
  alone; and leaving a voice channel forgot the keys of every channel the two
  shared, so simply changing rooms broke the text channels next door. A sender
  key now goes to a member of the named channel and nowhere else, members hand
  theirs over the moment somebody joins, and a leave only forgets the channel it
  was a leave from
- **A message that could not be decrypted is no longer passed on as history.**
  The placeholder was stored like any other message and handed to the next person
  to join, which spread one member's missing key down the whole chain of people
  who arrived after them. It now stays on screen for whoever could not read it,
  and is offered to nobody; incoming history is filtered the same way, because
  the peer on the other end may be running an older client
- **Asking for a channel's history again works when it is most needed.** The
  button required the other member's group key, which is not what a history
  hand-off travels over — so the one repair available after a key went missing
  was refused for the very reason it was being used. It now needs only the
  pairwise session it actually uses

### Security — a review before the release

Text channels and the second layout went through a full audit of the crypto,
the server and the seam between text and voice. What it found is below. None of
it had shipped.

**End-to-end encryption**

- **Shared history is bound to its channel, like everything else.** A hand-off
  named its channel only on the envelope the server writes, so a relay could
  take Alice's history of a private channel, label it as a public one Bob is in,
  and watch Bob merge it, file it, and offer it onward. The channel now travels
  inside the ciphertext and is checked against what the server claims
- **A client answers only members of channels it is in.** A request for history
  was answered on the strength of the user's own opt-in alone; a sender key was
  installed from anybody at all. Both now require that the channel is one we are
  in and that the other person is in it with us. It does not make an untrusted
  server harmless — it can still place somebody in a channel — but it has to do
  it where the member list shows them, instead of silently
- **Shared history is shown as second-hand.** There is nothing to check an
  archived message against: identities are per-connection and never written
  down, so nothing signs one. A member could therefore hand a newcomer an
  invented conversation attributed to somebody else, and it would be
  indistinguishable from what that person actually wrote. Merged history is now
  marked as what it is and stays marked when it is passed on, so a conversation
  still outlives its last original witness without a fabrication ever passing
  for first-hand
- **A message id cannot be squatted, or used as storage.** Two members'
  copies of a message are recognised by the id its sender minted — but the
  comparison ignored who sent it, so one member could shadow another's message
  by reusing their id. The sender is part of the comparison now, and an id
  arriving from the wire is bounded, rather than going into the encrypted
  archive at whatever length it was sent at
- **A message for a channel you just left no longer lands in that channel's
  archive.** Leaving while somebody was mid-sentence wrote
  "[encrypted message — decryption failed]" into the history of the channel you
  had left, with an unread badge and a sound. The check that drops such a
  message had been folded into the same step as the decryption, so failing it
  looked like a failure to decrypt
- **A far-future timestamp cannot silently disable history.** One message
  claiming the year 8000 — or an honest client with a dead clock battery —
  followed by clearing that channel set the "deleted up to here" mark past every
  future message, and nothing merged into that channel again. Timestamps are
  now bounded where they enter
- **The browser client and the desktop client share the code that was drifting.**
  The membership rules, the sender-key lifecycle, the message envelope and the
  history payload were written twice, once in Rust and once in TypeScript. Three
  of the faults above were that hand-port disagreeing with itself — including a
  rotation the desktop client performed and the browser skipped. There is one
  implementation now, in the WASM bridge the browser was already using

**The server**

- **One message can no longer disconnect a whole channel.** The relay re-wraps
  a client's ciphertext with a sender and a timestamp, which could push the
  result past the frame size every client refuses — so a single large message
  dropped the connection of everyone in the channel. Blobs are bounded on the
  way in, and the encoder refuses to emit a frame nobody could read
- **Text channels cost a budget.** A subscription is not a move, so joining and
  leaving one is not self-limiting the way changing rooms was: flapping it
  announced the change to every connected session each time. Subscribe/leave,
  the history-sharing flag, mute, deafen, the audio filter and channel options
  now each draw on a per-session budget
- **A connection can no longer hold every channel open.** Channels a user
  creates used to free themselves when their creator moved on; with
  subscriptions the creator can stay in all of them, and fifty of them is the
  server's limit for everybody. Creation is bounded per user, and the join rate
  bounds the trick of re-entering a channel to keep its deletion timer from
  firing
- **Malformed frames cost what valid ones cost.** A packet that framed but did
  not decode spent no rate-limit budget and wrote a log line, which made the log
  the cheapest thing on the server to fill. The budget is charged per frame now,
  and neither of those lines is written at info level
- **A request for somebody's chat history honours their answer.** The server
  broadcast the "I share history" flag and then never read it; a member who had
  turned sharing off was still asked, and repeatedly, by as many people as cared
  to. The flag is enforced, and the budget for answering belongs to the person
  answering
- **A fan-out no longer holds the lock every voice packet needs.** Broadcasting
  to a channel held the global channel lock across the whole send, and the lock
  prefers writers — so one person toggling mute could stall the media relay.
  Recipients are collected under the lock and sent to after it is released, as
  the media path already did
- **A channel that hides its members hides them on the way in and out too.**
  Joins and leaves are announced to everybody, because the same message doubles
  as the member count — and they carried the user id even where the name was
  blanked. With a `#general` everybody is in, every id has a name against it,
  so those ids alone rebuilt the member list a hidden or password-protected
  channel exists to withhold. An outsider is now told the count changed and
  nothing else
- **Both ends know the message budget.** The server charges a token per message
  and drops what cannot pay, quietly — and a client that means no harm can go
  over it just by arriving on a busy server, where it asks for a key bundle per
  person and then hands a key to each of them per channel. What it lost there
  was the worst thing to lose: a key that never arrives is a member who cannot
  read the channel, with nothing to say so. The rate is one number both sides
  are built from now, and each client keeps itself under it. The budget for
  relaying a key is also per recipient rather than per sender, because the cost
  falls on the recipient: handing a key to forty people is what honest software
  does, and sending forty at one person is not
- **Changing a channel's password or proximity mode costs what changing its
  other options costs**, and announces nothing when the value did not change;
  joining a channel is budgeted like leaving one; starting and stopping a
  screen share, both of which tell a whole channel, are budgeted at all
- **A game's audio filter keeps up with the game.** In a routed channel the
  client tells the relay who the player can hear, and that shares nothing and
  announces nothing — but it was drawing on the budget meant for the flags the
  server does announce, which allows two a second where the SDK documents
  twenty. The surplus was dropped without a word, so the relay went on culling
  by a filter the game had moved on from: somebody standing next to you that
  you cannot hear, with nothing on either screen to say why
- Smaller: a per-IP connect rate, pre-keys bounded at authentication as well as
  at upload, an abandoned channel-deletion timer that slept instead of being
  cancelled, ids that are refused rather than allowed to overwrite a live
  session or replace General, declining an invitation that was never sent no
  longer reaches the channel's creator, a duplicate login is no longer a log
  line anybody can ask for at will, and the widest broadcast on the server is
  built once rather than once per recipient

**A second pass over the same ground**, after the first one's fixes had been
written. Everything below came out of reading them again.

**Nothing limits how many conversations you can follow.**

- **The cap on text channels is gone.** A build between 0.8.0 and this one let a
  client hold sixteen at once. It was there to stop one connection creating
  channels and subscribing to every one, so that none of them ever emptied and
  expired — and it did that by charging the user for it, on a server whose owner
  had decided how many conversations it runs. The hoarding is answered where it
  happens instead: a channel starts its own deletion timer the moment it is
  created, so one nobody joins goes away by itself. Which was also a hole of its
  own — a channel whose creation succeeded and whose join was refused had no
  members and no timer, and stayed in the map for the life of the server. Enough
  of those and nobody could create a channel again
- **The budgets are sized from the server, not from a number.** Joining a
  channel, handing each one's members a key, asking each one's members for its
  history: every one of those has a per-session budget, and each is now derived
  from how many channels this server can hold. A client that connects and
  subscribes to all of them can pay for doing it once, whether that is five
  channels or five hundred
- **A server can be as large as its config says.** The ceiling on concurrent
  connections was a constant of 256, and ten per address, whatever `max_users`
  said — so a server told to take more users simply could not, with nothing in
  the log to say why. Both follow the configuration now: connections are
  `max_users` doubled, because a browser client holds two of them, and
  `max_connections_per_ip` (32 by default, so sixteen browser users behind one
  household or office address) is a setting rather than a constant
- **A reconnect no longer asks for the same channel twice.** Rejoining what you
  had open and joining what the server auto-joins are two paths to the same
  channel, and both ran; each one costs a join from the same budget, so a
  reconnect to a server with a handful of auto-joined channels could exhaust it
  and land you outside channels you had been in, with a wall of "slow down"
  where the chat should be

**Keys**

- **A channel can no longer end up with no media key at all.** The key is minted
  by the lowest-numbered member and re-minted by whoever is lowest after a
  leave — but re-minting was refused when we held no key to succeed, which is
  exactly the position the last remaining member is in when the one who held it
  disconnects. The channel then had no key, everyone who joined later elected
  the same member, who was still waiting, and nobody in that room could speak
  for as long as it existed. Holding no key is now the reason to mint the first
  one rather than the reason not to
- **A message written before the channel had a key is sent under the current
  one.** Messages typed before any member holds your sender key are kept and
  sent when one does. If somebody left in the meantime the chain they hold is
  the one those messages went out on — the rotation only ever ran for a message
  typed after it. It runs for these too now
- **A pre-key bundle is checked for size.** The key material a client uploads is
  opaque to the server and kept until they disconnect. Nothing bounded how long
  each piece was, so one client could park a hundred blobs of any size in the
  server's memory — and a bundle built from them was a message too long to send
  at all, which the requester was never told: they simply could never open an
  encrypted session with that person again
- **Everybody's budget for relaying keys to somebody forgets them when they
  go.** One rate limiter per person you have shared a channel with, and user ids
  are never handed out twice, so on a busy server a long-lived session
  accumulated one for every person who had ever passed through

**Smaller, all of them things that only show up under load or over a long
uptime:** the sweep that bounds the connect-rate table runs on a timer instead
of on every connect once the table is large, because it walks the whole table
and a flood of addresses otherwise makes every connection on the server pay for
it; a channel description in `channels.json` is bounded like a channel name,
since the channel list is one message and one over 64 KiB cannot be sent, which
would leave every client seeing a server with no channels at all; a message the
server builds and cannot frame says so in the log rather than vanishing; the
desktop client's outgoing control queue is no longer fixed at 1024 messages,
which a connect to a busy server could fill — the task that filled it is the one
reading the socket, so it stopped reading, and the server dropped the keys
arriving for it; and the list of text channels you have left keeps the newest
entries rather than the oldest, so leaving a channel on a well-used server is
not quietly undone at the next connect.

**Fixed: a channel two people joined in the same instant had no media key at
all.** One member of a channel mints the key and hands it to everyone else, and
the member who did it was "whoever is alone here" — but two clients arriving
together each see the other in their very first roster, so neither was alone,
neither minted, and nobody in that channel could speak until somebody left and
came back. It is now the same election that decides who re-keys after a leave:
the lowest user id in the roster. Ids only ever increase, so that is the
longest-present member and a newcomer never mints over a key that already
exists.


### Looking ahead

Accounts and server-stored history — so a conversation carries on while you are
offline — are the next step, and this release is shaped to leave room for them:
message ids live inside the encryption and are stable across every copy, the
merge and the deletion watermark work against any source, and chat is already
filed per server. Two things are deliberately not solved yet. Signal state is
ephemeral per connection by design, so ciphertext a server kept would be
unreadable after a reconnect: server-side history needs a long-lived per-channel
key shared between members. And accounts need a persisted identity with a way to
show when it changes. Neither is in this release.

### Added — a second layout, and it is the new default

VoIPC has always looked like TeamSpeak: channels on the left, members on the
right, voice and status bars along the bottom. That is a good layout and it is
not going anywhere — it is **Classic**, and it is one click away. It is also not
the shape most people arriving here have spent years in, so there is a second
one, **Modern**, inspired by the chat apps they come from. (A build between
0.8.0 and this one called it after the app it is shaped like. It has a name of
its own now, and a layout or palette chosen there is carried over, not reset.)

- **A modern layout**, beside the existing one and switchable at any
  time from Settings → Appearance. Server rail down the far left, channel
  sidebar with the people in **every** channel nested under it, chat in the
  middle, members on the right, and your own name with the mute and deafen
  buttons in the bottom-left corner. A click previews a channel and a double
  click joins it, the same as the classic layout — the two sidebars look nothing
  alike and behave identically, because they call the same functions
- **You can see who is where without going there.** The names for a channel you
  are not in are never pushed to this client — a join is broadcast to everyone,
  because it doubles as the user-count update, but it carries an empty username
  to anyone outside the channel it names, so that moving between an anonymous
  channel and an ordinary one cannot hand outsiders both names for the same
  person. So the sidebar asks, through the query the server already answers
  carefully: a channel that hides its members or carries a password tells nobody
  outside it who is in there, an anonymous one answers with its pseudonyms, and
  an admin is answered where everyone else is refused. Every one of those rules
  stayed on the server, which is where it was; the client only decides when to
  ask, and coalesces so a filling channel is one question rather than ten
- **Modern is the default**, and you are asked once, on the first connection,
  while you are still in the lobby where voice is off — after the audio setup,
  because a microphone nobody can hear is what ruins a call and a layout is not.
  A layout you picked is kept. If you never picked one there is nothing stored to
  keep, so you get the default and the question, and Classic is one click away in
  Settings → Appearance or from the server-name menu. Skipping is not an answer,
  so the offer stands next time
- **The virtual room, the mixing desk and a screen share open full screen** in
  the modern layout, the way an activity pane does, and close with Escape. The
  classic layout keeps them in the centre column. Both read the same selector,
  so the room button in one and the room button in the other are the same button
- **On a phone it is the phone shape you already know**: rail and channels swipe
  in from the left, members from the right, chat in the middle. Horizontal drags are the
  drawer's and vertical ones stay with the scroller, so the message list still
  scrolls at full speed; the mixer's faders and the room's avatars say they do
  their own dragging and are left alone. There are buttons for all of it too — a
  drawer you can only reach by swiping is a drawer some people cannot reach
- **The sidebars can be dragged**, in either layout, and each layout remembers
  its own widths. Double-click a divider to put it back. The member list folds
  away and stays folded

### Added — it does not have to be dark blue

- **Four palettes**: Slate dark, **Slate light** — the first light theme this
  app has had — VoIPC dark, and AMOLED black, which is genuinely black
  rather than very dark grey, for a phone where that is a pixel that is off
- **A new install follows the system.** Slate dark is the default, and on a
  machine set to a light theme the app opens in Slate light instead — browsers
  report it through `prefers-color-scheme`, Android and Windows pass it to the
  WebView. Consulted only when nothing is stored: a palette somebody chose is
  theirs, and sunset does not get to repaint it
- **Every colour can be changed**, one by one, and previews as you drag the
  picker. It is not a skinning engine; it is the seventeen custom properties the
  whole UI was already drawn from, with a colour input each
- **Compact messages** and a chat text size, and an interface zoom from 80% to
  150%
- **A palette cannot ship unreadable.** The unit tests hold every shipped
  palette to WCAG AA on the pairs that actually occur — text on each surface,
  the accent on a sidebar — and the browser test measures the contrast of a real
  channel name against the real sidebar behind it, in the light theme, in the
  live document. That is how the blurple in the Slate palettes ended up lighter
  than the one it was taken from: `#5865f2` is a fill colour with white on top,
  and as text on those greys it measures 2.99:1, which is why the apps that use
  it put blue links

### Changed

- **A server's `auto_join` text channels are actually joined now.** The join was
  fired from the channel list, which the server sends as part of logging in —
  while the client is still finishing its own connect, so the command was
  refused with "Not connected" and the `#general` a server wants everyone to
  land in stayed empty. It now waits for the connection, and the browser test
  covers it with a `channels.json` of its own
- **The modern layout fits a phone.** Found by testing on one, over a real
  server: it drew under the status bar and under the navigation bar, so the
  header collided with the clock and the user panel — with the settings gear on
  it — sat under the system buttons, where a tap opened the recents screen
  instead. The shell now keeps out of both insets. The push-to-talk bar, which
  is fixed to the bottom and makes room for itself nowhere, covered the message
  input and half the voice panel: the space it needs is measured from the bar
  itself now, in portrait and landscape. The member drawer opened a 130-pixel
  sliver rather than the full width. The Settings dialog was drawn under the
  push-to-talk bar, so its last rows could not be reached
- **Android's system bars belong to the app now.** `enableEdgeToEdge()` was
  called with no arguments, which reads the *phone's* day/night setting once at
  startup and paints a 90%-white scrim across the navigation bar — a cream slab
  under a dark app — and picks the icon colour to match the system rather than
  the app. Both bars are transparent with no scrim, and the status and
  navigation icons now follow the palette: dark icons on Slate light, where they
  used to be white on white and simply missing
- **Android stopped writing the call, and its keys, into logcat.** The logcat
  layer was registered with no filter at all. Two things came out of that. The
  volume: the JNI wrapper's three lines per call and quinn's per-packet tracing
  measured, on a phone idling in a voice channel, about 20,000 lines and 6.7 MB
  **per second** — 66 MB in the ten seconds it took to measure, now 0. And the
  contents: at `info` the Signal implementation writes base keys, prekey ids and
  sender-key distribution ids, and logcat outlives the session and lands in any
  bug report. In an app whose whole argument is that the keys stay with the
  people talking, that was the wrong place for them. The default is now our own
  crates at `info` and everything else at `warn`, so third-party problems still
  surface and third-party bookkeeping does not. `RUST_LOG` still overrides it
- **The leave ✕ and the channel settings gear appear without a hover**, which a
  touch screen does not have. On a phone the only way to reach either was to
  press and hold a channel row, and letting go joined the channel instead
- **Settings is in the server-name menu** in the modern layout, beside the
  layout switch — a second way in that does not depend on the bottom of a drawer
- **Picking a channel on a phone shows the chat**, in the modern layout too. The
  channel list is a drawer over the chat there, so a tap that only changed what
  was behind it read as a tap that did nothing. Both layouts answer the same
  request now
- **Neither layout is painted before the settings are read.** The window used to
  show the default shell for the length of one config round trip and then swap —
  invisible while the default was the one most people had, and not once it was
  the other one
- **The layout is now a component, and App.svelte is the event bus.** The two
  shells are siblings; everything under them — the channel dialogs, the member
  menu, the admin dialogs, the create form — moved into shared modules mounted
  once, so there is one copy of each however many layouts exist. ChannelList went
  from 861 lines to 386, UserList from 820 to 258, VoiceControls from 607 to 369,
  StatusBar from 368 to 150
- **Push-to-talk, Ctrl+M, Ctrl+D and the tray's toggles live outside both
  layouts now.** A layout is a subtree that is destroyed and rebuilt when you
  switch it, and doing that to the key handlers mid-call would either lose
  push-to-talk or leave two copies racing each other
- **Appearance settings are one stored object**, opaque to the backend and owned
  entirely by the frontend. It is the only setting written that way, and the
  reason it may be is that nothing on the other side reads it — so a new palette
  colour is a change in one language rather than five. Settings written by a
  newer build survive an older one saving over them

### Fixed

- **Muting yourself from the mixing desk did not mute you in the member list.**
  The desk set the flag directly instead of going through the helper that also
  patches your own row — which exists because the server deliberately does not
  echo your own mute back to you. So the desk said muted, the member list said
  not, and only a channel change made them agree
- **Android's volume-key push-to-talk opened the microphone without the app
  knowing.** It called the command directly and never set the transmitting flag,
  so the voice bar showed nothing and voice activation could not tell the
  microphone was already open
- **The phone's push-to-talk button worked in the lobby**, where voice is off:
  holding it started a capture task with nowhere to send
- **A mobile unread badge always fell back to a hard-coded red**, because it
  named a colour variable that has never been defined. Four more colours carried
  fallbacks that disagreed with the real value — dead today, and a trap for
  whoever renamed one
- **The channel settings dialog's checkboxes are addressed by name now.** The UI
  test clicked them by position in the list, so adding an option — or moving the
  dialog into its own file, which is what happened — would have quietly set the
  wrong ones and failed somewhere else entirely

## [0.8.0] - 2026-09-11

Protocol version 8 — client and server must be updated together. A channel can now ask the server to forward each voice only to the people who should hear it, which is a new channel option and a new client message; everything else here is client-side and would have shipped without a bump.

### Added — a mixing desk

Everything the game SDK could ask for was reachable by exactly one thing: a game. Now it is yours too, in any channel no game is driving.

- **A mixer takes the centre column**, the way the virtual room already does, with a tab of its own on a phone. One channel strip per lane, yours pinned at the front: a level meter beside a real vertical fader, a mute, an effect, and the three scalable effects under a disclosure. The faders are 44 px wide and at least 120 px long, so they can be used with a thumb
- **A lane is a lane.** Your microphone on the way out and each person's voice on the way in are the same thing pointed in different directions, so they carry the same four controls and nothing else: an **effect** (a preset), and **muffle**, **reverb** and **water** at 0–10 each. Reverb and water are scalable effects sitting beside muffle, not a room, not a bus and not a special case. The desk renders every strip from one template, and both the Rust mixer and the browser worklet assert that the two directions produce the same samples from the same settings
- **Thirteen effect chains instead of two.** Five radio grades (`radio`, `cb`, `walkie`, `aviation`, `police`), five phone grades (`phone`, `landline`, `mobile`, `badvoip`, `intercom`), plus `megaphone`, `gramophone` and `robot`. They are one parametric chain — band, drive, hiss, crackle, bit-crush, ring modulation, squelch — driven by a table, so a CB really does not sound like an aviation set, and a new voice is a row rather than a branch. Every id is a valid game-SDK `mode` and appears in `capabilities`
- **Per-source level meters**, so you can see who is loud before you reach for a fader
- **Radio, phone, the squelch and the room now render in the browser too.** One copy of the chain serves the worklet, the sender path and the tests, and both languages assert the same thirteen pinned levels, so the desktop mixer and the browser cannot drift apart unnoticed
- **A voice changer for your own microphone**, meaning all four controls and not just the effect. Everyone hears them: they are rendered into your voice before it is encoded, so no listener can switch them off, and they stay yours even while a game drives the channel. The microphone test plays the whole lane back to you
- **The only asymmetry left is who a setting reaches**, and it is not a control. Your own lane goes out to everybody; an incoming lane only changes what you hear, and a game takes the incoming ones over while it drives — the same speaker can be heard directly by one listener and over a phone by another, and only the game knows which. Faders and mutes stay yours throughout

### Added — routed channels, and what the server is told

A proximity channel a game drives can be a whole map. Every listener receiving and decoding every talker is the thing that stops it being one, so a channel may now ask the server to forward selectively. It is **off everywhere by default**, because it is the only state in which this server is told anything about who hears whom — and where it is on, the people in it are told, in the same words in the README and in the toast they get on the way in.

- **`routed`, a channel option** beside hidden, anonymous and hide-members, in `channels.json` and in the channel dialog, with a paragraph under the checkbox saying exactly what it shares. The channel list marks such a channel **R**
- **Two writers, one rule.** A client says which members it wants to hear (`SetAudioFilter`), which is what a game mod already worked out to cull the mix. A game server may also `POST /game/v1/routes` with a bearer token from `game_token`, and that one is authoritative — so a patched client asking for everybody gains nothing
- **Buses are opaque.** The game server hashes and salts its own names per run before sending them; the relay hashes them again, resolves "who may hear whom" on receipt, and forgets them. No coordinates, no ranges, no radio channel names, no job names — and the endpoint refuses a body with any field it does not know, so a coordinate cannot arrive by accident. There is deliberately no way to read anything back: a game token is not an admin token, and a `GET /sessions` would walk straight past an anonymous channel's pseudonyms
- **Fails closed per session, open per table.** Somebody a live table does not list hears nobody; but a table that expires, or was never posted, hands the whole channel back. The other way round, "stop the game server from posting" would be the whole attack
- **It is not cryptographic separation, and the README says so.** The channel still shares one media key: this stops packets reaching a cheat client, not a cheat client from reading the ones it does get. That is still strictly more than SaltyChat, YACA, TokoVOIP, TFAR or ACRE2 enforce, which is nothing
- **The endpoint is bounded by the roster.** Resolving buses intersects every listener with every speaker, so a body naming more players than the server can ever hold is refused rather than turned into a table of that size squared. An empty `game_token` is treated as no token — otherwise a placeholder in a settings file would have made a request carrying no credentials at all compare equal and pass. A table that has expired no longer gets a vote on whether the next `epoch` is new enough, so a game server that restarts without changing `boot` is not refused for ever, and a run of refusals is logged once rather than a few times a second
- **A client's "these are the ones I want to hear" goes when the channel does** — when they leave it, and when its `routed` flag is switched off — so switching routing back on cannot enforce an answer from another day against people who are not the same people any more

### Added — VoIPC asks about your audio once, instead of finding out mid-call

A voice app whose first call is "I can't hear you" has failed at the only thing it does. Everything needed to avoid that was already in Settings; what was missing was anybody being walked through it.

- **A four-step setup on the first connection**, while you are still in the lobby where voice is off anyway: which microphone (with a meter that says *we heard you*, or that you are clipping), which ears are which (a voice plays hard left, then hard right, and the screen names the side — so headphones on backwards is something you find out now rather than in a call), and how your microphone opens. On the web it asks for the microphone first, and a refusal is finally said out loud instead of becoming blank device names
- **Every answer is saved as it is given**, through the same per-setting command Settings uses. Quit halfway and you keep what you chose. **Skip is on every step**, and skipping leaves the offer standing rather than marking it done
- **The same screen is the re-pick** when a device you chose is unplugged: it opens on that one step and nothing else
- *Run audio setup again* in Settings, for when something changes
- **Push-to-talk key capture is one implementation now** (`lib/keybind.ts`), shared by Settings and the setup, with a test — including the case only push-to-talk has, where a bare Ctrl is the binding. It also warns when the key you picked is Ctrl+M or Ctrl+D, which also toggle mute and deafen
- **`start_output_test`**, which had no equivalent: the spatial test needs a connection and takes eight seconds to answer a question this answers in two

### Added — the rest of the games

- **[docs/GAMES.md](docs/GAMES.md)**: a row per game — how a mod reaches VoIPC there, whether it can see the other players or only its own, and what that costs. Three tiers: nine engines that can do everything (FiveM, RedM, alt:V, RAGE:MP, MTA:SA, Garry's Mod, Minecraft with a client mod, Unity, Unreal), three that can only see their own player and want beacon mode, and five where no client-side code is possible at all — which is the argument for a routed channel driven by the game server. Plus World of Warcraft, and why it is deliberately not shipped
- **MumbleLink**: some games write their own player's position into shared memory rather than letting a mod talk to anything. It takes the same "a game is driving" slot a mod's `hello` takes, so the two cannot write the listener's position at each other, and whichever arrives second is refused rather than fighting. Guild Wars 2 is the case worth having — ArenaNet writes it natively and documents it, so proximity voice there needs no addon and no grey area. VoIPC reads **the first 44 bytes and nothing else**: the fields after them name the player's game account and which server they are on, and what is not read cannot leak. A stale block (a game that closed without clearing it) stops the feed rather than freezing a position on the wire. Off by default, and it still only reaches other people if beacon broadcasting is allowed
- **Two compatibility shims.** `sdk/fivem-voipc-pma/` and `sdk/fivem-voipc-salty/` answer the export names pma-voice and SaltyChat answer. ESX, QBCore, Qbox and the ox resources are not voice integrations of their own — they call one of those two — so switching is: start the shim, stop the old resource, touch no framework script. Where the models genuinely differ (SaltyChat's secondary radio, per-resource volume, mic clicks, radio towers) the shim says once what it is not doing rather than failing quietly, and the natives no shim can stand in for come with the grep that finds them
- **Calls are groups, not pairs**, in the FiveM resource: a conference call is the same thing with three people in it, and both shims hand their callers a channel id rather than a partner. pma-voice lets a *client* name its own call channel and a call id is guessable, so that one path goes through a new `Config.canJoinCall` hook — default open, as pma-voice is, and documented as the thing to close
- **MTA:SA's origin** (`http://mta`, a bare host with no path — RFC 6454) is allowed out of the box, with a test that `http://mta.attacker.example` still is not

### Added — the game SDK grows a radio and a phone

A proximity plugin has always made you choose: somebody is *either* on your radio *or* standing next to you. VoIPC no longer asks.

- **Layers: one speaker, heard up to four ways at once.** A player entry may carry up to three `layers`, each a full spec of its own — position, range, volume, muffle, effect chain, **which ear**, and **how late it arrives** — all rendered from the one Opus stream. So a colleague two metres away who keys their radio is heard twice, as themselves and over the air; and the tinny earpiece of somebody's phone leaks *at their own head*, two metres from you, which is a thing no TeamSpeak plugin can express
- **`pan`**, −1 to 1, puts a render in one ear with no softening clamp: "the phone is at my left ear" is not an estimate, unlike a world direction. **`delay`**, up to 100 ms in 20 ms steps, is the radio arriving a beat after the voice in the room
- **`mode: "off"`** leaves a speaker out of the mix but keeps their layers, which is how a call partner on the other side of the map is heard at all
- **`{"type":"transmit","on":true}`** holds the player's push-to-talk while their in-game radio key is down, so they hold one key instead of two. Off until they allow it in Settings, it can never talk over mute, and it is let go when the socket closes, when another game takes the mix, when they leave the channel, or after 60 seconds — sending it again while the key is still down keeps a long transmission going, which is what the shipped resource does when it sees the 60 second release
- **Beacon mode** (`hello.mode: "beacon"`) is for games whose mods can see where *their* player is and nothing more: VoIPC broadcasts that one position to the channel, encrypted with the channel key like voice, and the other members place themselves. Off until the player allows it, and it sends at a constant rate so the relay cannot read "moving" and "away from the keyboard" out of the packet timing
- **`modes` beside `capabilities`** in the `state` reply: what `mode` accepts, without the feature flags mixed in, so a mod's dropdown lists chains rather than "layers, pan, beacon"
- **The FiveM resource does radio and phone for real**, and is the reference for layers. Membership, keying and the **job gate** live on the game server, because a FiveM state bag only reaches clients that have that player in scope — and the other end of a radio never is. `Config.canJoinRadio` and `addChannelCheck` are where a framework's job check goes; the VoIPC server is not told that radio channels exist

### Security — the game SDK, audited and tightened

Every one of these was reachable before this release. A mod is trusted to place people in the channel it named, and nothing else.

- **A refusal no longer names you.** `hello` with the wrong `server` answered with the player's user id, username and mute state — so any page on an allowed origin (every `cfx-nui-*` resource on every FiveM server, any `localhost` page, any local process) could learn who was at the keyboard, and find their server by guessing until the answer changed. It now carries the version and nothing else
- **Speaking and mute pushes stop at the channel the game joined.** They were keyed to a user id that was set once and never cleared, so a mod went on receiving who-talks-when after the player walked into a private channel, until its socket died. They are also now limited to the players the mod listed: the socket is not a directory of who is in the room
- **One origin owns the mix.** Ownership went to the newest `hello`, and every `cfx-nui-*` origin is trusted, so any other script on the same game server could take placement off the voice resource — and two of them fighting is silence, because each takeover clears every placement. A different origin is now refused while the owner's socket lives; the same origin still takes over, which is a resource restarting
- **`hello` must name a channel.** Without one a mod armed itself on whatever channel the player was in — including a private, non-positional one, where no banner says a game is driving and yet every voice can still be given an effect
- **The channel a game drives is protected properly.** `hidden` keeps it out of the channel list, which is discovery and not a lock: a player who knows the name could join it with no mod running and hear every talker at full volume, undistanced. The shipped `channels.example.json` now gives that channel a **password** as well, and the FiveM resource keeps it in a `server_script` — `config.lua` is downloaded to every player, so a password in it is a password everybody has. The server hands it to a client at the moment it joins, through a new `mayUseVoice` hook, at most once every five seconds per player. With `routed` on, a game server's table still silences anyone it does not list, in both directions
- **A player may be listed once.** On a server where players publish their own VoIPC id, a second entry for somebody else's id took over their voice: last write won, so they were heard at the claimer's position or culled out of everyone's mix. Refused now, on both sides — the shipped FiveM resource also ignores a claim on an id somebody else holds
- **The socket is rate-limited.** Nothing bounded `update` frames, each of which takes the lock the mixer needs every 20 ms; and a `hello` loop with a wrong password raised a toast per attempt. Updates are acted on at up to 50 a second, `hello` at one
- **A game's name cannot paint the UI.** `game` and `resource` went into a toast and a banner unfiltered; they are now capped at 32 characters with control characters, zero-width marks and both kinds of bidi override stripped
- **Taking consent back stops what is happening, not what happens next.** Both switches were read when the game next asked, so unticking *let a game press my push-to-talk* left the microphone open for up to a minute, and unticking *let a game broadcast my position* went on broadcasting until the mod's socket died. They now act at once — and switching the integration off, which is the escape hatch, lets go of a held microphone instead of leaving it open for the rest of the session
- **A game's release of the push-to-talk no longer makes the app forget your own key.** It raised the same event a global hotkey does, so the window stopped believing you were transmitting; your key release then closed nothing, and the microphone stayed open — reachable by any mod merely connecting, whatever it was allowed to do. It also could not be made to churn the capture device: a press too soon after the last one is dropped, and a socket that has been replaced by a newer one can no longer release the microphone the new one is holding. A *release* is never dropped, though. Rate-limiting that edge as well would have been the same bug from the other side: a game's key handling runs once per frame, so a tapped radio key is a press and a release about 16 ms apart, and dropping the release left the microphone open until the 60 second cap out of one tap
- **One origin may hold two sockets, not all of them.** Every `cfx-nui-*` page is a trusted origin and a socket that pings never times out, so a third-party script could hold every slot and the voice resource's next restart would be answered `503` for the rest of the session. Eight sockets in total, two per origin, and a `hello` loop against the rate limit now closes the socket instead of being answered for ever
- **`set_position_sync` is refused while a game drives.** Only the checkbox was disabled, not the command underneath it — and taking that path would have cleared the game's placements and started broadcasting a position the *game* chose
- **A peer's position beacon is checked before it is decrypted**, so a flood of them costs no AES-GCM while we are ignoring them anyway

### Added — a mod you can run instead of a game

- **[`sdk/test-mod.mjs`](sdk/test-mod.mjs)**, a fake mod in one dependency-free file. It drives the whole pipeline against a running client — `hello` joining the named channel, an update placing two players with a radio and a phone layer, a duplicate id refused, `transmit` opening and closing the microphone, a second origin refused the mix — and prints a line per rule in [docs/SDK.md](docs/SDK.md). `sdk/test-page.html` is the one with sliders; this is the one that answers "is it me or is it VoIPC" in ten seconds

### Added — you can see what the game is doing

- **A toast when a game takes over**, naming it, its resource and the channel it just moved you into — and, if you have allowed either, that it is broadcasting your position or may press your push-to-talk. The only sign before was a line in a settings panel nobody has open
- **Culled members are greyed out** in the member list and the mixer, with "out of earshot in the game". A game says who is in earshot by leaving everyone else out — which is how distance culling works, and also how a hostile one would silence a person. Switching the integration off hands everything back
- **The voice bar says when the game is holding your microphone**, in a different colour from a key you pressed yourself

### Fixed — three of these shipped with a passing test

- **The reverb was inaudible.** Its send used a constant lifted from Freeverb, which normalises an eight-comb bank differently; measured, the wet path sat about 35 dB under the dry at every setting — **−34.8 dB at level 3, now about −18.5**. The send is now normalised by the comb bank's own broadband gain. The old test asserted the energy was above 1e-6, against a value of 3.8e-3: three orders of magnitude of slack while nothing was audible. It now asserts a wet-to-dry ratio in dB
- **The underwater slider was an on/off switch.** Its cutoff swept from 22 kHz, so the first half of the travel sat above the voice band: steps 1 to 5 moved a 1 kHz tone by 0.83, 0.86, 0.93, 1.11 and 1.49 dB. The cutoffs are now solved backwards from the filter response for an even step, and **every notch moves it between 2.7 and 3.7 dB**
- **The effects panel's close button did nothing.** It sat inside the panel's drag header, whose pointer capture retargeted the click away from it. The panel is gone, and the UI test now drives every control with real mouse events instead of `el.click()`, which cannot see pointer capture at all
- **Per-user volume existed twice and disagreed.** The member menu and the panel each kept their own copy. There is now one store, and a test that fails if a second writer appears. Every lane setting goes through the same store, so the same guard covers the effects
- **Reverb and water were on a bus rather than on a lane.** They were applied once to the finished mix, which meant they could not be put on one person, and the microphone had a second, differently-shaped copy of them. Each lane now carries its own delay lines, the mix-wide pass is gone, and a game's `self.reverb` and `self.underwater` override every incoming lane for as long as it drives
- **A preset's first frame ramped its level** instead of starting at it, because the makeup gain was applied after the gain was primed. Caught by the cross-language pin
- **The mixer was unusable in a narrow window.** Its layout switched on the *window* width, but it lives in the centre column between the channel list and the member list — at 700 px that column is barely 300 px, so the desktop layout went into a third of the space it needs and strips ran off the side and painted over each other. It now switches on its own width with a container query, strips stack and scroll, and the fader takes a row of its own when there is no room beside it. The UI test grew lanes at 900, 700 and 600 px that measure the geometry: no strip outside the mixer, no two strips overlapping, the stack scrolling, and the fader at least 40 px each way
- **Turning placement off was a way to hear through walls.** Unticking *Hear people where they stand*, or being in a channel that is not positional, discarded the game's distance culling, its per-player volume and its muffling in one go — while the radio chain kept playing. Those settings take away direction and distance, which is what they are about; they no longer take away the game's judgement that somebody is behind a wall, or not in earshot at all
- **The reverb never went idle.** It reported "still audible" from its *settings* rather than from its tail, so a lane with the reverb turned up kept the mixer awake for ever and ran the comb bank on subnormals through every silence. It now answers with the tail, and zeroes its delay lines on the way out. The same rule now decides whether the bank runs at all: a lane whose reverb was turned back down, or that is only underwater, does not pay for four combs and two allpasses per sample — which it did for the rest of its life, and for the microphone's own lane that meant the rest of the session
- **A lost packet no longer squelched a radio in the browser.** A loss burst was counted as a pause, so the chain closed the transmission and opened it again on the next packet that arrived: two squelch bursts in the middle of a sentence a desktop listener hears whole
- **The microphone test's self-monitoring played the effect and nothing else.** It ran the old effect-only path, so the muffle, reverb and water you had set on your own lane were missing from the one place you can hear yourself before anybody else does — and in the browser it shared its filter state with the live sender, so transmitting during a test stepped the filters on every frame that went out
- **A game's first `hello` told its own socket it had been detached.** Joining the channel the `hello` named is a channel change, and the "a game stopped driving" event that follows dropped the user id the reply had just handed out: no speaking pushes, and `transmit` answered "send hello first", until the mod said hello a second time
- **A layer's delay could only ever grow.** Lowering `delay` mid-sentence left the line at the length it had reached, so the layer stayed late until the speaker paused
- **A channel change while a game was beaconing re-armed position sync in the new channel**, because the game's borrowed sharing was handed back after the change had switched sharing off, rather than before
- **The player's own meter was dead during the microphone test**, which is the one moment it matters: it polled the capture task's level, and the test refuses to run while the capture task does. It now follows the test
- **`proximity` was misreported to mods and never pushed.** A player with placement switched off was told `"3d"` — the exact field the docs tell a mod to read — and the field only ever appeared in a reply to `hello`, never when it changed. Both fixed, and the docs no longer claim effects are silent in a channel that is not positional, because they are not
- **A second microphone test inside a minute lost its first half-second**, because the sidetone restarted its numbering while the browser's mixer was still waiting for the next frame
- **A push-to-talk key bound to Ctrl+M muted the microphone it had just opened.** The two shortcuts had no idea the PTT binding existed
- The browser's mixer tab was missing from the type that lists mobile tabs, and the browser and Rust reverbs were pinned against different noise, different targets and a tolerance eight times wider. They are now measured the same way, against the same three numbers, to ±0.5 dB
- **The device pickers in Settings showed the system default**, not the device you had chosen — so the panel claimed you were on the default when you were not
- **The end-to-end browser test had never opened the Settings panel or a microphone test.** It now drives the whole audio setup — the meter, both ears, the mode — and the Settings panel, which is how a missing screen would have been caught in the first place
- **`npm run build` works again on a distribution that ships FFmpeg 9.** `ffmpeg-next` was pinned to 8.1, which cannot compile against FFmpeg 9: its enums grow variants the crate's exhaustive matches do not cover, so the build died in fourteen screens of `non-exhaustive patterns` inside generated bindings, minutes in, with nothing in it naming FFmpeg. Arch moved to 9.0 on 3 September and every native Linux build here has needed an `FFMPEG_DIR` pointing at an 8.x tree since. The pin is now 9.0, which builds against FFmpeg 9 **and everything older** — one pin for this machine, for the Ubuntu runner on 6.1 and for the Windows prebuilt on 8.1 — and needed no code changes. Every build path also checks the major before compiling now, the Linux one included, so the next FFmpeg major says so in a second rather than in C errors ten minutes in
- **A desktop binary built with a bare `cargo build` says so.** Without the Cargo feature `npm run build` passes, the UI is not embedded and the window loads the Vite dev server instead — with none running, the entire window is the browser's "Could not connect to localhost: Connection refused", while the app behind it runs normally and its game-SDK port answers. It looked like a broken app and was a build that was never finished; it now prints a line saying which build to run instead

### Removed

- The listener-wide room, and with it the `set_room_fx`, `set_sender_room` and `set_sender_effect` commands. Reverb and water are per lane now, and one command each way — `set_user_fx` and `set_mic_fx` — carries all four controls. The saved settings `room_reverb`, `room_underwater`, `mic_underwater` and `sender_effect` are replaced by `mic_effect`, `mic_muffle`, `mic_reverb` and `mic_water`; an older config loses whatever was set on the old room bus and starts clean
- The floating effects panel, its drag, its viewport clamping, and the per-user **range** and **ignore distance** controls. Distance and placement belong to the virtual room, which already owns them — having them in two places is what made them contradict each other. The `set_user_position` command keeps both arguments for the game SDK; nothing in the UI sends them now, so range stays at its 20 m default unless a game sets it

## [0.7.0] - 2026-09-09

Protocol version 7 — client and server must be updated together (a channel now carries a proximity mode and four options, and positions travel as a new encrypted media packet). A 0.5.x client connecting to a 0.7 server is told to update and stops reconnecting.

### Added — channel options

Four options per channel, in `channels.json` or through the channel's gear icon (its creator, or an admin; channels from `channels.json` have no creator, so those are admin-only). They are what an ingame roleplay channel needs, and they compose: see the `Ingame` entry in [channels.example.json](channels.example.json).

- **`hidden`** — the channel is not listed for anyone but admins. It can still be joined through an invite link or by the game SDK, so it is out of the way rather than locked
- **`anonymous`** — members see each other as `Guest-1234`, a fresh name each time they enter. **The substitution happens on the server**, in every message that carries a name: the member list, joins, chat, direct messages, pokes, invites and screen-share notices. No other client is ever told the real name, and you see your own pseudonym too, so you know what the others see. Admins see the real names, which is what makes moderating such a channel possible. Chat history is not handed over in an anonymous channel: the names in an archive sit inside the ciphertext, where the server cannot substitute them
- **`screen_share`** — `false` refuses sharing in that channel, and the button disappears there
- **`hide_members`** — non-admins get no member list and no head count, only whoever is speaking (for about ten seconds), so a voice can still be turned down without the room being a roster. Members still receive the list internally, because the encryption keys are exchanged per member

### Fixed

- A refused screen share no longer leaves the sharer permanently marked as sharing. The flag was set before the channel was even looked up, so any later refusal locked that session out of sharing until reconnect

### Added — proximity chat

- **A channel can place voices in space.** Its mode is `off`, `2d` (a floor plan) or `3d` (height counts too), chosen when the channel is created and changeable afterwards by its creator — or by an admin, which is also the only way to change a channel from `channels.json`, exactly as with their password. Set `"proximity": "2d"` on an entry in `channels.json` to have a room start that way
- **Voices are panned and attenuated on the receiving client**: the constant-power pan law browsers use for `StereoPannerNode`, the inverse distance model FMOD and TeamSpeak 3 use, Mumble's near-field bloom so someone standing on you does not spin around your head, and a fade over the last stretch of the range so a voice crossing it does not click. Gains ramp across each 20 ms frame; a source nobody placed sounds exactly as it did before, at unity on both channels
- The formula lives once per host — `crates/voipc-audio/src/spatial.rs` and `client/src/lib/spatial.ts` — and both assert the same golden table, so the desktop and the browser cannot drift apart. The browser check runs in the end-to-end test
- **The playback path is stereo end to end.** A mono output device gets the downmix, a surround device the front pair. **Android plays the downmix for now**: distance works there, panning does not
- **A virtual room** shows the channel on a top-down plan (plain SVG, no new dependency). Arrange everyone yourself and the layout stays on your machine; turn on *Sync my position* and you move only yourself while your position is broadcast to the channel. Presets: round table, class room with a presenter at the front, line, free placement. In a `3d` channel each avatar gets a height slider
- **Positions are as private as voice.** A shared position is one 39-byte AES-256-GCM packet under the channel key, relayed like a voice datagram: the server sees that a member is sharing a position and nothing else. It is re-sent once a second so a late joiner converges, at most ten times a second while moving, and the server drops it entirely in a non-proximity channel
- **Per-viewer choice for screen-share audio**: it can come from where the sharer stands or stay centred, toggled in the viewer's toolbar or in Settings. Spatial audio as a whole can be switched off per client, which matters on a mono headset or with hearing in one ear
- **A server-wide switch**: `proximity_enabled: false` in `server_settings.json` serves every channel as non-positional, refuses requests to enable it, and stops relaying positions
- **Try it without a second person**: Settings → Spatial Audio → *Test 2D* / *Test 3D* sends a synthetic voice circling you through the real mixer, with a live readout of where it is. Turning "Hear people where they stand" off while it runs is the A/B comparison. On desktop it needs a connection (it plays through the call's mixer); Android hears the distance but not left/right

### Added — a game SDK, as the open alternative to the TeamSpeak plugins

- **A game mod can drive the positions.** VoIPC opens a loopback WebSocket that a page inside the game runtime connects to, the way SaltyChat, YACA and TokoVOIP work — but with no plugin to install, no license server, and players addressed by their VoIPC user id instead of by matching nicknames
- One bulk update a few times a second carries the listener's pose and every audible player with their range, volume override, 0–10 muffling and mode. A player left out of the list is silent, which is how distance culling works in the plugins scripts already target. Radio, phone and megaphone audio is `mode: "radio"`, `"phone"` or `"direct"`, and the handshake's `capabilities` list says what a build actually renders
- **Radio and phone are real effects now**, not flat audio: `mode: "phone"` band-limits a voice to roughly 300–3400 Hz, and `mode: "radio"` adds drive, a faint hiss and a short squelch burst when a transmission starts and ends. Deterministic and click-free; the browser client has no SDK and renders both flat, which is what `capabilities` is for
- **Positions glide between updates.** A mod sending 4–10 times a second used to step the pan and the volume at exactly that rate; each player (and the listener's own pose and facing) now moves smoothly over the gap between updates. A jump of more than 50 m snaps instead, so a respawn does not sweep across the room
- **VoIPC pushes back**: `talk` for another player starting or stopping, `self` for the local player's speaking, mute and deafen, `user` for someone else's mute. Enough for a talking icon over a player's head. "Speaking" means voice actually going out, so push-to-talk and mute are reflected
- **`hello` now waits for the join.** It used to answer `ingame` before the channel was joined, so a wrong password looked like success and left distance culling armed with nobody driving it. A refusal is relayed verbatim: `could not join Ingame: incorrect channel password`
- **Off by default**, loopback only, and origins are checked: the game runtimes are allowed by prefix, `localhost` and `127.0.0.1` only as the exact host, and everything else is refused — a page served from `localhost.example.com` is an ordinary internet page that can reach a local port like any other. `hello.server` is required, so a mod cannot skip the wrong-server check by leaving it out, and the newest connection that completed a handshake owns the mix: a refused or stale socket can no longer clear a running game's positions on its way out
- After a VoIPC reconnect the mod's player ids belong to the previous session; VoIPC answers such an update with an error telling it to say hello again, instead of silently culling every speaker out of the mix
- **Hardened the socket**: a handshake must finish in 5 seconds, a silent socket is closed after 30, at most four are served at once, `Upgrade` and `Sec-WebSocket-Version: 13` are checked, client frames must be masked as the standard requires, and a first frame pipelined behind the upgrade request is no longer thrown away. A port that cannot be bound is reported in Settings instead of leaving the toggle on and nothing listening
- **A ready-made FiveM resource** in `sdk/fivem-voipc/`: state-bag identity, head-bone positions at 10 Hz, distance culling, muffling from vehicles, interiors and line of sight, and a voice-range key. Radio, phone and the talking overlay are left as documented stubs. `sdk/test-page.html` grew the channel field, the radio and phone modes, the build's capability list and a live "who is talking" line
- `docs/SDK.md` documents the protocol and the FiveM/alt:V/RAGE identity flow

### Fixed — hardening of the above, before it ships

- **The web client no longer wedges when a channel is created.** The session cached the channel-list array it also handed to the UI, so a later in-place update duplicated a channel; Svelte's keyed list threw inside its flush and every later update threw again, leaving the window dead. The event bus now hands out copies, and both list updates replace instead of appending blindly, which also covers the server's snapshot and broadcast racing on two simultaneous joins
- **Proximity chat now works on the desktop client at all**: the mixer only learned a channel's mode from the channel list and from later edits, never from joining one, so voices stayed flat and no position was ever shared. Joining also drops the previous room's placements, as the browser already did
- **Changing a channel's proximity no longer deletes its password.** Saving the settings dialog always rewrote the password with the empty field; it is now left alone unless you type one or tick *Remove the password*
- A dragged avatar sends at most ten positions a second on both clients, instead of one per pointer event — most of which the server dropped, the resting position among them
- A newly created mixer source no longer bursts at full volume for its first 20 ms: gains start at their target instead of ramping down from unity, so a locally muted or distant speaker stays quiet
- The browser client applies the saved spatial-audio settings on load, ignores non-finite positions (one NaN silenced a source for good), and the room view no longer keeps sharing your position after *Reset*, leaves a stale selection behind when someone leaves, or shows *Sync my position* as on when the toggle failed
- The room view now locks while a game drives the positions, which the game SDK had announced since the beginning with nobody listening

### Fixed — Android

- **A channel can be joined on a phone at all.** Joining is a double click, and the page is zoomable, so Android read a double tap as double-tap-to-zoom and never delivered the event — you could highlight a channel and nothing else. The channel row now opts out of that gesture
- **The Android build compiles again.** `tauri::Manager` was imported only on desktop, and the new game-SDK event publishers use it everywhere; nothing had compiled the Android target since that landed, because no CI job does. Verified end to end this time: built, installed on a phone, connected to a 0.7.0 server, joined a channel

### Fixed — older bugs, while we were in here

- **Muting or deafening yourself shows on your own row at once.** The marker in the member list only appeared after a channel switch, because the server deliberately does not send `UserMuted` back to the session that caused it and no client filled the gap; the toolbar button looked right the whole time, which is what made it confusing. Toggling from the Android notification now updates the button as well, which it never did
- **Firefox can share a screen or a window again.** The browser client asked for the shared screen's audio unconditionally, and Firefox — which has never implemented that capture (Mozilla bug 1541425) — answers by offering browser tabs and nothing else. It is no longer asked for there, and the share dialog says why and points at a Chromium browser for anyone who needs the sound

### Changed — build tooling

- `npm run release` no longer stops dead when Docker is missing. It falls back to a host build of the web bundle and the server, names the AppImage as the artifact it had to skip and says why it is worth having (the image exists to pin glibc 2.39 so one build runs everywhere), and warns that the host server is not the static musl one. `VOIPC_NO_DOCKER=1` takes that path on purpose
- The artifact summary lists what the run actually built. It used to print the whole `release/` directory, so last month's tarball was reported as fresh output
- `npm run version:check` now also covers the FiveM resource manifest and the two copies of the SDK's `state` example, which had been drifting by hand

### Fixed — CI, which had never finished a release

- **The Windows release job is the build that actually works.** It built natively on a Windows runner against FFmpeg from vcpkg — a path that shared no code with `npm run build:windows` and had never once succeeded. vcpkg follows FFmpeg head and is on 9.0.1; `ffmpeg-sys-next` 8.1 stops at libavcodec 62, so every attempt compiled for eight minutes and then died in the bindings, after a forty-minute FFmpeg build that a failing job never got to keep. Windows is now cross-built on Linux by the same task run at home, with FFmpeg pinned to 8.1 and its ABI major checked before anything compiles against it, and a small Windows job installs the resulting installer and checks the app starts. Only NSIS is built; the MSI bundle had never been produced anywhere
- **The Rust test job installs the client's dependencies.** `npm --prefix client test` was added as "no dependencies to install", which stopped being true when the store tests landed: they reach `svelte/store` through `room.ts` and `users.ts`, so on a runner's fresh checkout the step died instantly on `ERR_MODULE_NOT_FOUND`
- **`clang-cl` is no longer assumed.** Arch ships that name, Debian and Ubuntu ship only `clang` — and clang picks its cl driver mode from `argv[0]`, so the cross build links one itself instead of failing its tool check on a distribution it should support
- **Caches survive a failed job.** `actions/cache` only saves on success, which is why every red Windows run threw away the expensive part and started over; the caches that guard a long download or build now restore and save separately
- **A red build says what went wrong.** Reading Actions logs through the API needs admin rights on the repository even when it is public, so a failure was a black box to anyone without push access. Every build and test step now runs through `tools/ci-run.sh`, which repeats the tail of a failure as an annotation — those need no credentials at all. `test-web.sh` has done this for its browser lanes since 0.5.2
- **The Opus SIMD workaround reaches the build again.** `xwin-msvc-toolchain.cmake` disables Opus' SSE4.1/AVX dispatch paths, which clang-cl refuses to compile without a target-feature flag, and it was selected through an environment variable whose name contains dashes. That is not a valid shell identifier: `dash` drops such variables from the environment it passes on and `bash` keeps them, so the override survived on Arch (`/bin/sh` is bash) and silently vanished on an Ubuntu runner (`/bin/sh` is dash) — Opus then compiled its SSE4.1 sources and the Windows build died with four errors nobody could see. It now comes from `.cargo/config.toml`'s `[env]`, which cargo puts straight into the build script's environment with no shell in between, and the wrapper finds cargo-xwin's own toolchain through the variable cargo-xwin itself sets instead of reassembling the path. The Android task already used the underscored spelling and was never affected
- **The Windows smoke test looks where the installer actually puts the app.** It was carried over verbatim from the native-Windows job, which was skipped on every run it ever had, so it had never executed once: it looked for `VoIPC.exe` under `%LOCALAPPDATA%\Programs\VoIPC`, while Tauri's NSIS installs in currentUser mode to `%LOCALAPPDATA%\VoIPC\voipc-client.exe`. It now reads the install location and binary name back out of the uninstall key the installer writes, so it stays correct if those defaults change, and reports any failure as an annotation the way the Linux side does. Launching the installed app is reported but does not fail the job yet — nothing has yet observed a Tauri window surviving on a runner session

### Testing

- The spatial maths is asserted along a full 2D and 3D trajectory in both languages, not just at a few fixed points, and the browser copy is checked in the end-to-end run
- `npm test` in `client/` runs the browser-side unit tests on Node's own runner (no new dependency)
- `test-ui.mjs` drives the real Svelte UI in a headless browser — creating a proximity channel, arranging the room, joining with a second client, changing the mode — and fails on any uncaught error. The end-to-end script runs it in its Chromium lanes; it reproduces the wedging bug above on the unfixed code

## [0.5.2] - 2026-09-08

Protocol version 5 — client and server must be updated together (one QUIC connection per client, media headers without the UDP token, loss reports, the share's codec). A 0.4 client that connects to a 0.5.2 server is told to update and stops reconnecting, and so is a build from the unreleased 0.5.0/0.5.1 trees: they speak protocol 5 but without the codec field, which the server checks by exact version match.

### Added — screen sharing in every browser

- **Any browser can watch a screen share.** A share now states its codec (`StartScreenShare`), the server hands it to each viewer when they start watching, and the viewer builds its decoder from that. Desktop sharers encode **H.264 by default**, which every client decodes — Firefox included, and Chromium on Linux, neither of which has ever had an HEVC decoder in WebCodecs. H.265 stays available under Settings → Screen Share for rooms where everyone watches from a desktop client; a viewer that cannot decode a share's codec is told which codec it is and that the sharer can switch, instead of being left with a black frame
- **Browsers can share their screen.** `getDisplayMedia` → WebCodecs → the same encrypted fragments the desktop client sends, one QUIC stream per frame. VoIPC picks the codec by actually encoding a frame with it: Chromium shares H.264, Firefox falls back to VP9 because its WebCodecs H.264 encoder reports support and then refuses to encode ([Bugzilla 1918769](https://bugzilla.mozilla.org/show_bug.cgi?id=1918769)). Desktop audio comes along where the browser offers a track (Chromium for tabs and system audio; Firefox on Linux offers none). The frame clock runs in a Worker, so a share keeps its frame rate while the tab sits in the background — where a sharer's tab lives, and where page timers are throttled to about one tick per second
- The browser share honours the same viewer-count gating, keyframe requests and quality ladder as the desktop sharer, and drops a frame rather than sending one too big for the 255-fragment wire format (WebCodecs has no VBV)
- Encoders and decoders are wired for H.264, H.265, VP8 and VP9 across all three clients — FFmpeg on the desktop, MediaCodec on Android, WebCodecs in browsers
- **The end-to-end browser test now shares and watches a screen.** `BROWSER_ALICE` / `BROWSER_BOB` pick the engine per side, so one run covers Chromium sharing to Firefox and the next covers the reverse; all four pairings pass. An animated canvas stands in for the display, so headless runs need no real capture
- Windows builds now install FFmpeg with `x264` alongside `x265` (`.\setup.ps1`, and the cached vcpkg build in CI); Linux gets libx264 with the distribution's libavcodec

### Added — a default server for demo builds

- `VITE_DEFAULT_SERVER=host[:port]` at build time pre-fills the connect dialog, so a build handed to someone points at your relay from the start. Unset — as in every tagged release — the dialog starts at `localhost:9987` in the desktop app and at the page's own origin in the browser. Works for the desktop, web, Android and Docker builds; the release workflow takes it as an optional `default_server` input when run by hand (see BUILDING.md)

### Changed — native clients over QUIC
- **Desktop and Android clients now connect over QUIC (WebTransport), the endpoint the browser client already used.** The TCP control connection and the raw UDP media socket are gone: control messages travel on one bidirectional stream, voice and screen-share audio as QUIC datagrams, and every video frame on its own unidirectional stream — in both directions, so the server relays the same thing for every client. TLS 1.3 only
- **One UDP port for everyone.** The QUIC endpoint listens on `udp_port` (default 9987, same number as the page's TCP port); `web_port` and UDP 9988 are gone (an old `server.toml` with `web_port` still loads, the key is ignored). Native clients ask for the operator certificate by TLS server name and pin it on first use exactly as before — existing pins keep working; browsers keep getting the short-lived hash-pinned certificate on the same endpoint
- **NAT rebind, keepalive and dead-UDP detection replaced by QUIC.** Connection migration survives NAT mapping changes and address changes (Wi-Fi roams), keepalives are QUIC's, and a blocked UDP port now fails the connect with a clear error instead of leaving a session that is silently mute and deaf. The `udp_token` / address-learning machinery, the loopback bridge for browser sessions and the dead-UDP toast are removed; the status-bar latency comes from QUIC's own RTT estimate
- **Media headers shrink by 8 bytes** (voice 17 → 9, video 23 → 15, screen audio 21 → 13 plus 2 for the key id when encrypted): the UDP token they carried no longer exists. The server checks that a packet's session id is the sending connection's own instead
- Disconnecting closes the QUIC connection explicitly so the server frees the username immediately
- The `voice_load` example drives QUIC clients and sends encrypted voice (it used to send plaintext, which the server drops); the TCP `test_client` example is gone

### Added — screen-share congestion control
- **Viewers report frame loss to the sharer every 2 s** (native and browser viewers alike) and the sharer steps its encoder down a ladder — 60%, 40% and 25% of the configured bitrate, with the frame rate halved on the two lowest rungs — instead of answering loss with ever more keyframes. A sharer whose own uplink queue backs up counts that as loss too. After 30 s without loss it climbs one rung back. Level changes are logged
- **Only a majority of the viewers steps a share down.** Reports are counted over a 2 s window against the current viewer count, so one viewer on a bad link (or one lying about it) no longer costs everybody else quality
- **The sharer also watches its own QUIC path**, which viewer reports cannot see: once a second it compares lost packets against packets sent and the round-trip time against the session's minimum, and treats ≥1% loss or a doubled RTT as congestion. The send queue is half as deep as before (about a second of video), so backpressure is reported sooner instead of hiding a growing backlog
- Keyframe requests are now capped per share rather than per viewer: one relayed request per second however many viewers ask, which ends the keyframe storms a crowded share used to trigger

### Changed — screen-share bandwidth and latency
- **A periodic keyframe every 4 s instead of every second**, roughly a quarter less video bandwidth at 1080p30. Video travels on reliable QUIC streams, where loss no longer breaks the decoder chain, so the periodic keyframe is only a safety net — and every viewer joining a share now gets one on the spot (still at most one per second per share), rather than only the first
- **Video fragments are relayed and decoded as they arrive.** The server and both clients used to read a whole frame's stream before parsing it, so every hop added the frame's full transmission time — 35 ms for a delta frame and up to 300 ms for a keyframe on a 5 Mbps link

### Security
- **A QUIC connection slot is only spent once the client's address is validated.** The slot used to be taken on the first packet and held for the whole 10 s handshake window, so spoofed source addresses could pin all 256 of them and lock everyone out. Unvalidated sources now get a Retry first, which costs one extra round trip on a first connect

### Fixed — Android
- **The Android app started and immediately died.** The native library needs the NDK's C++ runtime (the audio layer is C++) but never declared it, and Android's loader resolves only what a library declares — so `dlopen` failed with `cannot locate symbol "__cxa_pure_virtual"` before the first screen was drawn. Shipping `libc++_shared.so` inside the APK was not enough. The build now links it, and the Android build task refuses to package a library that does not
- **Watching a screen share showed "Waiting for video stream..." forever.** Frames were being received and decoded the whole time; the viewer converted them to RGBA and the JPEG encoder rejects an alpha channel ("does not support the color type `Rgba8`"), so every frame was dropped on the way to the screen. It converts to RGB now
- **A share that was not a multiple of 16 wide decoded sheared or stretched.** The decoder is configured before the first frame with a 1920x1080 guess, and on a device that does not report a stride, that guess survived as the row stride of a 720p picture. The stride now follows the real size, and the codec's crop rectangle is applied, so a 854-wide share is shown as 854 and not as the padded 864
- The connect dialog on Android and Windows offered `tauri.localhost` as the server, the app's own internal webview origin. It offers `localhost` again; only the browser client fills in the page's origin

### Fixed
- **A kicked or banned client is told why again.** Ending a session waited for whichever of its legs finished first, and on a kick that is always the media relay, so the control leg was cut off while it was still delivering the reason. The client showed a plain "connection lost" instead of the kick message, most of the time in Firefox and occasionally in Chromium
- Screen-share and voice relay no longer take a detour through a loopback UDP socket for browser sessions
- The web client says so when the browser has no WebCodecs audio decoder, instead of staying silent as if nobody were talking; the H.265 probe also accepts the `hvc1` spelling of the codec, which some browsers advertise instead of `hev1`
- Firefox is now covered by the browser end-to-end test (`BROWSER=firefox ./test-web.sh`): voice, chat, direct messages, invites, history and admin kick all pass on Firefox 155

## [0.4.0] - 2026-09-04

Protocol version 4 — client and server must be updated together (client-generated media keys, nonce domain separation).

### Added — web client
- **VoIPC runs in the browser.** Point a browser at `https://your-server:9987` and you get the same app: channels, voice, E2E chat, DMs, pokes, and screen-share viewing. No install, no extension. The server binary embeds the web client, so hosting it is not a separate deployment
- **Same crypto as the native clients** — the Signal Protocol (libsignal) and AES-256-GCM media encryption are compiled to WebAssembly and run in the page. The server relays the same encrypted bytes it relays for desktop clients and can read no more than before
- **HTTP/2 and WebTransport, no HTTP/1** — the page is served over HTTP/2 on the existing TLS port; control messages travel on one WebTransport (QUIC) stream and media as QUIC datagrams, with each video frame on its own stream. The TLS listener now offers only `h2` to browsers, so HTTP/1 requests are refused during the handshake. The WebTransport endpoint listens on UDP `web_port` (default 9988; `0` disables the web client) with a short-lived certificate the server generates and rotates itself and publishes by hash to the page — operators configure nothing beyond opening the port
- **Browser media pipeline** — Opus encode/decode and H.265 decode via WebCodecs, capture and mixing in AudioWorklets with the same 20 ms clock and jitter buffer as the native mixer. Where a browser cannot decode H.265 (Linux browsers today) watching a share says so instead of showing a black frame; voice and chat work everywhere
- **Not in the web client:** sharing your own screen, the pop-out viewer, global hotkeys, the tray, and the encrypted chat vault (browser chat is in-memory only). Everything else is the desktop feature set. Needs Chrome 97+, Edge 98+, Firefox 130+ or Safari 26.4+ (WebTransport and WebCodecs)
- Notification sounds in the browser: built-in tones per event (Settings → Sounds), no files needed; phones other than Android (iPhone, iPad) get the mobile layout
- `build-web.sh` builds it (wasm + Vite + server), `test-web.sh` runs a headless two-browser end-to-end check of voice, chat, DMs, invite links, history hand-off and an admin kick, and `./release.sh` now also emits `release/VoIPC-web-<version>.tar.gz`

### Added — moderation without accounts
- **Admin sessions.** Any connected user can log in with the server's admin token (status bar → shield). Set `admin_token` in `server.toml`, pass `--admin-token`, or export `VOIPC_ADMIN_TOKEN`; without one the server prints a fresh random token in its log at every start (like a TeamSpeak privilege key). Admins are visible to everyone (shield badge), can kick users from any channel or from the server, and ban an IP for 1 h, 24 h or until restart. Bans live in server memory only, apply to TCP and WebTransport connections alike, and can be lifted from the admin panel. Three wrong tokens disconnect the session
- Kicks and bans carry a reason; the client shows it and does not auto-reconnect afterwards

### Added — onboarding
- **Invite links**: `https://your-server:9987/#channel=<name>[&password=…]`. Opened in a browser it lands in the web client with the channel pre-selected and joins it right after connecting; the desktop connect dialog accepts the same link. The fragment never leaves the browser (not sent to the server, not in its logs). *Copy invite link* sits in the channel-list header; the password rides along when your session knows it, otherwise the joiner is asked
- **Channel history for newcomers**: on joining a channel, one member hands you the last 50 channel messages over your pairwise Signal session (end-to-end; the server relays ciphertext between members only). They appear above a "shared by …" divider and are deduplicated against what you already have. Opt out under Settings → Data. Direct messages are never shared

### Added — UI
- **Saved servers** — the connect dialog keeps a list of saved servers (★ Save); click an entry to connect
- **Fullscreen screen-share viewing** — button or double-click, in both the in-app viewer and the pop-out window
- **Microphone test** — level meter in Settings → Audio Input, works without joining a call
- Errors are now surfaced as toasts (connection-loss reason, kick/shutdown message, device/channel/chat failures) instead of silently landing in the console
- Auto-reconnect keeps trying for 5 minutes (was 30 seconds) — survives Wi-Fi roams and laptop sleep; Cancel still available

### Added — quality of life
- **System tray** — closing the window now hides to the tray and the call keeps running; tray menu offers Show/Hide, Toggle Mute, Toggle Deafen, and Quit (Quit actually exits)
- **Desktop notifications** — DMs and pokes show an OS notification while the window is unfocused (first launch asks for permission); DMs also flash the taskbar like pokes
- **Global mute/deafen hotkeys** — optional system-wide hotkeys (Settings → Global Hotkeys) that work while unfocused or in the tray, using the same evdev/rdev machinery as PTT
- **Mic input gain** — capture-side gain slider (0–400%) next to the output volume; applies live, also visible in the settings mic test
- **Voice quality indicator** — the status bar shows packet-loss percentage next to the ping (colored: <1% normal, 1–5% orange, ≥5% red), fed by the jitter buffer's conceal counts
- **Dead-UDP detection** — if keepalive Pongs stop for 35 s while TCP stays up, a sticky warning explains that voice/UDP is blocked (firewall/NAT) instead of silent mute/deafness; clears itself on recovery
- **Chat next to screen share** — watching a share no longer replaces the chat: it appears in a collapsible pane under the video (desktop)
- **Copyable links in chat** — URLs in messages are highlighted; clicking opens a copy dialog with the URL preselected (links never open a browser directly)
- **Skippable chat vault** — the first-run encrypted-history setup can be skipped ("don't save chat history"); chat then stays in memory only. Re-enable under Settings → Data
- Version-mismatch errors now say which version the server runs and that the client needs updating

### Changed — screen share encoding performance
- **Windows builds now include hardware H.265 encoders** — vcpkg FFmpeg is installed as `ffmpeg[x265,nvcodec,amf,qsv]`, enabling NVIDIA NVENC, AMD AMF, and Intel QuickSync (previously every Windows user encoded on the CPU with libx265). NVENC/AMF load from the GPU driver at runtime; QSV ships the Intel oneVPL dispatcher DLL. Re-run `.\setup.ps1` to pick up the new features
- Encoder rate control: VBV (`maxrate`/`bufsize`) is now set on all encoders so keyframes stay under the 316 KB UDP fragmentation ceiling (previously oversized keyframes were truncated, corrupting the stream); hardware encoders get an explicit 2-second GOP instead of the FFmpeg default IDR-every-12-frames; `forced-idr` ensures app-requested keyframes are real IDRs; libx265 `keyint` follows the actual frame rate instead of hardcoded 30
- Fixed Intel QuickSync producing no video: the frame converter now outputs the encoder's pixel format (NV12 for QSV) instead of always YUV420P
- Fixed keyframes being silently discarded on Linux under send backpressure — `Handle::try_current()` fails on the dedicated encode thread, so the fragments were dropped and the viewer stayed frozen. The encode thread now waits for channel room in a loop that stays interruptible by the shutdown flag, so a congested uplink cannot outlive a stop/switch and strand the pipeline
- Linux capture now paces to the requested frame rate — compositors running at high refresh (e.g. 144 Hz) no longer drive capture/encode at full refresh for a 30 fps share
- Windows capture loop paces at the top of the loop, so capture errors no longer busy-spin at 100% CPU
- Frame converter is rebuilt when the source resolution changes (window resize / portal renegotiation no longer garbles or crops the stream)
- Capture buffers are recycled between capture and encode threads (previously the steady state allocated a full frame per capture, ~110 MB/s at 1080p30)
- The media-key mutex is no longer held across fragment/encrypt/send, removing a contention path that could stall voice while sharing
- 60 fps shares get +50% bitrate (previously 60 fps used the same bitrate as 30, halving per-frame quality)
- Server per-session video rate limit raised from 120 pkt/s (~1.2 Mbps — silently dropped most of a 3–5 Mbps stream and caused keyframe-request storms) to 1200 pkt/s burst 400 (~12 Mbps ceiling); note this raises the per-session UDP forwarding ceiling accordingly
- `pipewire` crate bumped 0.8 → 0.10 (0.8 fails to build against libclang ≥ 19)

### Changed — voice pipeline & network resilience
- **Clocked voice mixer** — remote voice and screen-share audio are now decoded and mixed on a 20 ms clock (per-user jitter buffer → Opus decode → per-user gain × master volume → single playback ring) instead of each UDP packet racing to push PCM directly into playback. Fixes garbled audio when several people talk at once and gives screen-share audio jitter/reorder protection
- **Opus in-band FEC** — a lost voice packet is now reconstructed from the FEC data carried by the packet that follows it, falling back to packet-loss concealment only when the next packet is also missing
- **Adaptive jitter buffer** — buffering delay grows under observed late packets (40 ms → up to 160 ms) and decays after quiet periods; sender-restart and large sequence jumps resync quickly instead of playing seconds of concealment noise
- **Audio device hot-recovery** — capture and playback streams are rebuilt automatically when a device dies (unplugged headset, default device change); the UI shows an error toast while retrying and a restored toast on success. Output device changes now apply live without reconnecting
- **Non-48 kHz devices work** — capture and playback resample to/from the device rate (previously such devices played pitch-shifted audio or failed); WASAPI loopback screen-share audio is resampled too
- **NAT rebind** — the server re-learns a session's UDP address when its NAT mapping expires and reopens on a new port (previously voice died until a full reconnect); a UDP keepalive every 10 s keeps mappings alive through silent channels
- **Real latency display** — the ping shown in the status bar is now a true UDP round-trip on the media path (previously it compared the server's clock against the client's, showing clock skew)
- Voice nonce sequence persists across PTT presses (an AES-GCM nonce could previously repeat after a restart of the counter)
- Server relays voice packets without re-parsing the payload and no longer holds the channel lock across sends (a join/leave can no longer stall voice for everyone)
- Speaking indicators are edge-triggered (one event per talk burst instead of one per packet)
- Connect has a 10 s deadline per phase (TCP, TLS, auth) — a black-holed host no longer pins the reconnect loop and its Cancel button for minutes
- The TCP reader times out after 150 s without data (two missed server pings), so a silently dead path (Wi-Fi roam, laptop sleep, NAT expiry) triggers auto-reconnect instead of a frozen session
- The UDP receiver survives `recv` errors (Windows reported `WSAECONNRESET` after any ICMP unreachable and voice died for the rest of the session)
- Concurrent connects (reconnect loop vs. manual connect) are serialized; the loser's tasks no longer leak
- A second `connection-lost` during a reconnect (server shutdown is followed by the socket closing) no longer hides the reconnect overlay while the retry loop keeps running; cancelling a reconnect discards an attempt that was already in flight
- Signal state is reset on every connect. Identities are ephemeral by design; keeping the store across a server restart made libsignal reject peers whose reassigned user id had belonged to someone else
- TOFU pins are keyed by `host:port` (two self-signed servers on one machine no longer read as a MITM of each other) and can be forgotten from the connect dialog after a legitimate certificate change
- Server per-IP connection cap raised from 5 to 10: a browser holds two slots (the HTTP/2 page connection and the WebTransport session), so the old cap allowed only two web users behind one NAT

### Security
- **Media keys never touch the server.** Until now the server generated every channel's AES-256-GCM key and sent it to each joiner over TLS, so a server operator could decrypt all voice, video and screen-share audio despite the "blind relay" claim. The first member of a channel now generates the key on the client; existing members hand it to each joiner over their pairwise Signal session (`DistributeMediaKey`, which the server relays without being able to read). The server-issued `ChannelMediaKey` message is gone. Re-keying when a member leaves is not implemented yet (the server stops relaying to them; on-path capture of later packets would still decrypt) — planned as a follow-up
- **Fixed AES-GCM nonce reuse across media streams** — voice, screen-share audio, and video encrypt under the same channel key but kept independent sequence counters, so talking while screen-sharing produced identical key+nonce pairs on different plaintexts. The packet-type byte now domain-separates the nonce, and screen-share frame/audio counters persist across shares instead of restarting at 0. Old and new clients cannot decrypt each other's media — update all clients together
- **No plaintext media, ever.** Voice, video and screen audio were sent unencrypted whenever no media key was installed (e.g. the moment after a channel switch in voice-activation mode), and receivers accepted plaintext packet types even with a key present. Senders now drop frames until a key is installed (the UI shows a warning if that takes more than 2 s) and both the server relay and the client receiver drop the plaintext types
- **UDP source check on the client.** The receiver accepted datagrams from any address; anyone who learned the client's endpoint could inject packets or spoof keepalive replies. Only packets from the server's UDP address are processed
- **Relay no longer leaks `udp_token`.** Every forwarded voice/video packet carried the sender's secret UDP token in its header. Combined with the new NAT rebind, a channel member behind the same public IP (CGNAT, office NAT, shared VPN exit) could rebind — hijack or black-hole — another member's voice. The server zeroes the token before forwarding
- **Server hardening:** TLS handshake timeout (idle TCP sockets could hold all 256 connection slots forever); a malformed frame length now disconnects instead of growing the read buffer without bound; control-message sends are non-blocking so one client that stops reading can no longer stall broadcasts (and, through DashMap shard locks, the whole server); a failed `Authenticated` write no longer leaks the reserved username/session; pre-key bundle requests are rate-limited (one user could drain anyone's one-time pre-keys in seconds); pokes share the chat rate limit; keyframe requests are capped at ~1/s per viewer and only honoured from actual viewers of that share (previously a viewer could force ~50 IDRs/s onto a sharer); a kicked user's screen-share state is torn down like on leave (a kicked viewer kept receiving video)
- **Client:** a client-forged UDP Pong is no longer relayed as voice (it spoofed RTT/keepalive on every receiver); peer text is escaped before it reaches OS notification bodies (freedesktop daemons render markup)

### Fixed
- A rejected channel join (wrong password, channel full) no longer drops the current channel's media key and channel state — the switch is applied only once the server confirms it. Previously voice went silent until the next successful channel change
- Tray *Toggle Mute* / *Toggle Deafen* did nothing (event names didn't match the listeners)
- Voice-activation / always-on mode did not restart the microphone after a reconnect
- Releasing the PTT key while focus was in the chat box left the microphone open
- Switching between sharers could freeze the video until the next keyframe (screen-audio packets updated the sharer tracker without resetting the frame assembler)
- The sticky "UDP blocked" warning survived a successful reconnect
- Global PTT (evdev): unplugging the last keyboard made the listener spin at 100 % CPU and flood the log; PTT is released if it was held at that moment
- Server: the auto-delete timer aborted its own task, sometimes cancelling the `ChannelDeleted` broadcast; unanswered invites of users who disconnected stayed in the invite list forever
- Auto-connect never fired for users who skipped the encrypted chat vault (it waited for an unlock that could not happen)
- Removed dead code: `ts3_bridge.rs` (uncompilable), Signal state persistence (`persistence.rs`, never called), two unused Tauri commands
- Dropdown menus rendered with a native white background and gray text on Linux — WebKitGTK ignores themed `<select>` styling unless `appearance: none` is set; all selects now render dark with a custom chevron
- The client crashed on startup when no appindicator library was installed (libappindicator-sys panics on load) — the tray is now optional: without it the app logs a warning and closing the window quits instead of hiding to tray
- The client crashed on NVIDIA + Wayland ("Gdk Error 71 dispatching to Wayland display") — WebKitGTK's DMA-BUF renderer is now disabled by default (`WEBKIT_DISABLE_DMABUF_RENDERER=1`, overridable via the environment)
- `setup.sh`/`build.sh`/`dev.sh` only worked on Ubuntu/Debian: setup.sh now also supports pacman (Arch), the build scripts use the npm-installed tauri CLI (`npx tauri`) instead of requiring a global `cargo tauri`, and the bindgen include path is derived from `gcc -print-file-name=include` instead of a hardcoded Debian path; `release.sh` fails fast with a clear message when docker is missing
- `android-build.sh` had another machine's SDK path hardcoded (`ANDROID_HOME=/home/lukas/...`) plus a Debian-only `JAVA_HOME` and a global `cargo tauri` dependency — it now honors `ANDROID_HOME`/`ANDROID_NDK_HOME`/`JAVA_HOME` from the environment, auto-detects them from common install locations (newest installed NDK wins), uses the npm-installed tauri CLI, errors clearly when something is missing, and parses `debug|release`/`--target` in any order; it also sets `CMAKE_POLICY_VERSION_MINIMUM=3.5` so libopus configures under CMake 4
- **Added `android-setup.sh`** — one-command Android bootstrap for a fresh machine: installs commandline-tools, platform + build-tools (following `compileSdk` from the tauri-generated gradle file), the pinned NDK, a bundled Temurin JDK 21, accepts licenses, and adds the Rust cross-compile targets; re-runnable, everything env-overridable
- **Added the missing `ndk-arm64-toolchain.cmake`** — `android-build.sh` always referenced it but the file was never committed, so Android builds failed on any machine but the original one (libopus configured with no compiler); it's a thin wrapper over the NDK's official toolchain pinning `arm64-v8a` / `android-26`

## [0.3.0] - 2026-04-19

### Added
- **Android app** (Tauri 2 Mobile) — full mobile client: Oboe audio capture with RNNoise, `VoiceService` foreground service, volume-key PTT, tabbed mobile UI, `MobilePTT.svelte`, speakerphone toggle, and `android-build.sh` producing universal debug/release APKs
- **Persistent channels** — server can load a `channels.json` defining long-lived rooms (name, description, password, max_users); plaintext `password` fields are SHA-256-hashed on first load and the file is rewritten atomically (`channels.example.json`, `crates/voipc-server/src/channels.rs`)
- **TOFU certificate pinning** — `TofuCertVerifier` in the client pins self-signed cert fingerprints per host on first connect
- **IPv6 support** — client address parser accepts `[host]:port`, rustls `ServerName` uses `IpAddress` for IP literals, server UDP socket binds dual-stack when `host` is IPv6
- **XDG-compliant data directory** — `settings.json` and `chat_history.bin` moved to `~/.config/VoIPC/` (Linux) / `%APPDATA%/VoIPC` (Windows); legacy files next to the executable are migrated on first launch (fixes AppImage where the exec dir changes on every run)
- **Chat history setup flow** — `ChatHistorySetup.svelte` + configurable `chat_history_path`, so users can pick where the encrypted archive lives
- **Server connection limits** — global cap (256) and per-IP cap (5) on TCP connections
- **UDP rate limiting (server)** — per-session token-bucket rate limiters on voice and video packets
- **Graceful shutdown (server)** — Ctrl-C broadcasts `ServerShutdown` to all connected clients before the accept loop exits
- **Android runtime permission prompts** — `RECORD_AUDIO` requested at startup; JS-side toast feedback on denial via `__voipc_permission_denied`
- **Security audit documents** — `audit-desktop-todo.md`, `audit-server-todo.md`, `audit-android-todo.md` tracking findings and fixes

### Changed
- UDP address-cache hits now re-verify `udp_token` on every packet (closes spoof-based session hijack); sessions are bound first-address-wins
- Sender-key and media-key distribution verify both sender and recipient are channel members before the server relays
- `TofuCertVerifier` keys the pin store by canonical lowercase DNS name or standard IP string instead of the rustls `Debug` format (cross-version stable)
- Video packet parser rejects `fragment_index >= fragment_count`, zero-fragment packets, and unknown packet types
- Frame assembler and jitter buffer use wraparound-safe distance checks for `u32` sequence / frame-id overflow
- PTT "held" detection re-verifies the main key (not just modifiers) and the Linux evdev loop re-enumerates devices when keyboards are hot-plugged
- Signal Protocol tracking state is cleared on disconnect and reset on reconnect (prevents stale sessions from surviving a reconnect)
- Windows WGC screen capture now reuses the staging D3D11 texture across frames and only reallocates when dimensions/format change
- Opus encoder returns an error instead of panicking when the PCM frame size is wrong
- Config directory creation falls back to the OS temp dir instead of panicking when `~/.config` is unavailable
- Poisoned-mutex recovery (warn + `into_inner()`) applied consistently across client-side locks
- Android `MainActivity` sets `MODE_NORMAL` + speakerphone on by default for VoIP calls; `network_security_config.xml` restricts cleartext traffic

### Fixed
- IPv6 literal addresses were rejected by the old `host:port` splitter
- Chat history and settings were lost on AppImage upgrades because the exec dir changes each run
- Various DM/poke edge cases around reconnect — Signal state was not cleared, causing sender-key mismatches on re-established sessions

## [0.2.0] - 2026-02-16

### Added
- **Poking** — encrypted poke notifications, with popup UI and sound alert
- **Config persistence** — all settings saved to `settings.json` in the VoIPC data directory (`~/.config/VoIPC/` on Linux, `%APPDATA%/VoIPC` on Windows)
- **Configurable notification sounds** — per-action enable/disable and volume control for channel switch, user join/leave, messages, pokes, and disconnect
- **Auto-reconnect** — exponential backoff with visual reconnection overlay on connection loss
- **Docker release build** — `Dockerfile.release` and `release.sh` produce a static server binary (musl) and portable AppImage client
- **UI overhaul** — centralized icon system (`Icons.svelte`), design tokens in CSS, redesigned VoiceControls, UserList, ChatPanel, ChannelList, and SettingsPanel components
- **Server-client version check** — server validates client `app_version` during handshake and rejects incompatible clients
- **Global Push-to-Talk keybind** — PTT hotkey via `rdev` crate works system-wide, even when the app window is unfocused; configurable from settings
- **Windows screen capture improvements** — desktop/window source picker UI, hot-swap source selection, fix for GPU adapter mismatch in DXGI capture

### Fixed
- Receiving DMs and pokes in channel 0 (off-by-one in channel membership check)

### Changed
- Removed plaintext `SendChannelMessage` and `SendDirectMessage` protocol variants — all messages are now exclusively end-to-end encrypted
- Added `SendPoke` / `PokeReceived` protocol messages (encrypted via Signal Protocol)
- Added `app_version` field to the protocol handshake message
- Build scripts updated (`build.sh`, `build.ps1`, `dev.sh`, `dev.ps1`)

## [0.1.0] - 2026-02-15

Initial public release.
