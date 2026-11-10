# A real Discord move test (1.11)

`setup.mjs` fills an empty Discord server with everything the importer reads, so one real run checks the whole
move: roles, gates, members, bans, emotes, stickers, messages, threads, forum posts, pins, reactions and the hostile
corners. This page is the test plan. Tick each box, and for each ✗ write one line and take a screenshot.

What it cannot make: members and their own posts. Discord gives bots no way to, so a second Discord account (A) is
needed; a third (B) and fourth (C) cover a member who left and a ban. Posts by "Ada", "Bob.Builder" and so on come
from webhooks: the importer files them under that name with no account, as it would a real server's webhooks.

## 0. Before you start

- [ ] Relay on **1.11.0-rc.2** with accounts and `cloud = true`, `[accounts] public_url`, a certificate browsers
      accept, and `VOIPC_OAUTH_DISCORD_ID` / `VOIPC_OAUTH_DISCORD_SECRET` (docs/MOVING.md, "The address and the certificate").
- [ ] Your VoIPC account holds `*` and has two-factor codes on, and **has Discord linked** (*Your account*), so the
      run gives you your groups instead of making a second account for you.
- [ ] The Discord application: the one your relay signs in with. Bot tab: **Server Members Intent** and **Message
      Content Intent** on, **Public Bot** off. The script stops if an intent is off.
- [ ] A new server in Discord: *Add a Server → Create My Own → For me and my friends*. Do not pick a template: the
      script refuses a server that is not empty.
- [ ] Discord *Settings → Advanced → Developer Mode* on, so *Copy User ID* shows on right-click.
- [ ] Node 18 or newer on the machine that runs the script.

## 1. Build the server (about 15 minutes, most of it `#bulk`)

```sh
DISCORD_BOT_TOKEN='…' node testkit/7-discord-test-guild/setup.mjs
```

Or leave the variable out and paste the token when asked (it is not shown), or `--token-file <file>`. The token goes
to discord.com only and is never printed or stored. The script:

1. checks the application's intents;
2. prints the invite link (Administrator, as the wizard's) and opens it: pick the new server there;
3. waits for the bot to join, checks the server is empty, and builds. A stop or a crash loses nothing: run the same
   line again and finished steps are skipped (a step cut halfway may post a few things twice);
4. prints an invite link for your other accounts.

It turns on **Community** for announcement, stage, forum and media channels (`--no-community` to skip; those
four are then left out). Ids and webhook addresses go to `target/discord-test-guild/<server id>.json`. Delete that file
together with the server: the webhook addresses in it can post there.

- [ ] It ended with "Done. Skipped: nothing". If it skipped something, copy the lines into your report.

## 2. People and their own posts

Accounts: **O** you (the server owner), **A** the helper, **B** the one who leaves, **C** the banned one. A is
needed; B and C are optional.

1. A and B join with the invite link. C does not join.
2. Give roles (ids by right-click → *Copy User ID*):
   ```sh
   node testkit/7-discord-test-guild/setup.mjs members --mod <A's id> --plain <B's id>
   ```
   A gets Moderator, VIP, Members, Gold.Star, the unicode role, Event Host, Emote Artist and the nickname
   `Mod.Nick`. B gets Members. You already have Announcer and the unicode role.
3. In Discord, by hand:
   - [ ] O in `#general`: `O-1 hello from the owner`, then reply (Discord's Reply) to Ada's first post with
         `O-2 a reply by the owner`, and react 👍 to Ada's first post.
   - [ ] A in `#general`: `A-1 my first post`, then `A-2 hello @O` (a real mention of you), then a thread on A-1
         named `A's thread` with `A-3 in my thread`.
   - [ ] A in `#vip-lounge`: `A-4 in the VIP room`.
   - [ ] A in `#general`: `A-5 delete me after the import`.
   - [ ] O pins A-1.
   - [ ] B in `#general`: `B-1 I leave before the run`, then B **leaves the server**.
4. [ ] Ban C: `node testkit/7-discord-test-guild/setup.mjs members --ban <C's id>`.

## 3. Run 1 (desktop app: *Server admin → Discord move*)

- [ ] **Token step**: the token is accepted; *Cancel* during the check leaves nothing behind.
- [ ] **Dry-run** finishes, with a count of about 400 messages and a time estimate. Its notes should include
      (wording may differ, report any missing or surprising one):
  - `#old-forum`: a text channel here, its posts threads in its archive, tags do not come;
  - `#Town Hall`: a voice channel here, where a stage's moderators may speak;
  - @everyone could do more on Discord than a member can here by default;
  - the bot's own role does not come;
  - `@Event Host`: nothing here for MANAGE_GUILD, MOVE_MEMBERS, MANAGE_WEBHOOKS, MANAGE_EVENTS, MANAGE_THREADS,
    PIN_MESSAGES, BYPASS_SLOWMODE; `@Emote Artist`: nothing here for CREATE_GUILD_EXPRESSIONS;
  - the owner had power by owning the server, not by a role;
  - `#hidden-from-muted`: hidden from @Muted; `#member-overwrite`: a rule for one person; `#many-roles`: more roles
    than one gate holds; deny rules listed;
  - private: `#vip-lounge`, `#mod-chat`, `#mod-log`; `#history-closed`'s messages start off; the private thread
    never moves.
- [ ] **What comes**: everything on, Anonymise on. Then:
  - `#leave-me-out`: Leave out. `#messages-off`: messages off.
  - Private ones: tick `#vip-lounge`; leave `#mod-chat` and `#mod-log` unticked.
  - The risk text is shown in full before the tick.
- [ ] **The run** after a code: on SQLite the copy's path is shown (`<database>.before-import-<run>`). Write down how
      long it took: ______.
- [ ] **End screen** lists what came and what was left out.

## 4. After run 1: what came

**Channels**
- [ ] The five categories, with their emoji names; Discord's own `Text Channels` / `Voice Channels` with `general` and
      `General` too.
- [ ] Two channels named general (in Chat and in Archive) and `über-straße_💬`: how each is named here: ______.
- [ ] `#off-topic` slow mode 30 s, `#nsfw-test` 18+, `#announcements` announce-only, `Lounge` at most 5, `Town Hall`
      a voice channel, `#old-forum` and `#media` text channels.
- [ ] Topics came (`#general`'s, `#bulk`'s).
- [ ] `#leave-me-out` is not there. `#messages-off` is, with no archive.
- [ ] `#vip-lounge` only for the VIP group, `#mod-chat` / `#mod-log` gated, `Streamers` screen share only for VIP,
      `#read-only` speak only for Announcer.

**Groups**
- [ ] Every role a group, with colour, order and badge; none of them holds privileges.
- [ ] `Admin-power`, `Moderator-power`, `Role Keeper-power`, `Emote Artist-power`, `Announcer-power` exist, held by
      nobody yet. `Event Host` got no power group, or an empty one (everything it had is lossy).
- [ ] `Gold.Star` and `Gold_Star`, the 100-character name, `Ünïcødé ✨ Rôle`: how each came: ______.
- [ ] `crowd-01` to `crowd-17` came.

**Members**
- [ ] *Still to sign in* lists A, with the name `Mod_Nick` or what it became: ______.
- [ ] B is not a member here; B's post `B-1` reads as a former member's, with no name or id.
- [ ] C is a disabled account `dc-<C's id>`, on the Users tab's *Banned* filter only.
- [ ] You were not given a second account.

**Emotes and stickers**
- [ ] `vt_wave`, `vt_heart`, `VT_Caps`, `vt_spin` (moves), `vt_blink` (moves), `vt_vip_only` (Discord limits it to
      VIP; what happens here: ______).
- [ ] Stickers `vt-sticker-png`, `vt-sticker-apng` (moves), `vt-sticker-gif` (moves).

**The archive pane** (in each channel, beside the chat, labelled "Imported from Discord, unverified. This server can
read it.")
- [ ] `#general`, in order: Ada's hello; Bob's markdown; the two Bobs; the unicode post; the bot's reply to Ada (shown
      as a reply); Fox's mentions, with your name, `@Moderator` and `#off-topic` in place of the raw ids; the @everyone
      post; the embed's title; `[poll: Does the poll question come over?]`; `[sticker: vt-sticker-png]`;
      `[attachment: Ünïcode notes (1).txt]` and `[attachment: picture.png]`; the nine posts by `[admin]* tricky`; the
      2000-character post; 🔥🔥🔥; the `vt_wave` emote alone (big); the edited post (its new text); the timestamps
      post; the long name; `[forwarded]` Announcement one; your O-1, O-2, A-1, A-2, A-5, B-1 (former member).
- [ ] The post "Deleted on Discord before any run" is **not** there.
- [ ] Hostile posts show as plain text: no picture loads, no script runs, the `javascript:` link does nothing, the
      right-to-left and zero-width ones do not fool the name in front of them.
- [ ] Pins: Ada's hello, the embed, the files post, A-1.
- [ ] Reactions: Ada's hello shows counts for 👍 (2, with yours), ❤️, 😂, `vt_wave`, `vt_spin`; 🔥🔥🔥 carries 20 different reactions, all 20 shown (20 is the cap on both sides).
- [ ] `#threads-test`: `Public thread from a message` (10 replies), `A thread with no starter message` (3), `Archived
      and locked thread` (3), the 100-character title, `Thread whose starter was deleted` (2 replies, no starter),
      `A's thread` in `#general` (A-3). `Private thread: never moves` is **not** there.
- [ ] `#old-forum`: three posts as threads, replies inside, no tags.
- [ ] `#announcements`: two posts and the thread `Talk about announcement one`.
- [ ] `#bulk`: all 300, in order. Search `bulk 0150` finds one.
- [ ] Search for `[admin]*` and for `tricky` find that persona's posts.
- [ ] `#vip-lounge`: three VIP posts and A-4. `#mod-chat`: no messages (unticked). `#history-closed`: none (off).
- [ ] The text in `Lounge`'s chat, the scheduled event, the automod rule and Discord's join messages did **not**
      come.

## 5. A signs in

On a second device or browser, as A:
- [ ] *Continue with Discord* → Discord → back. The name screen offers A's name: ______. A recovery key is shown.
- [ ] A sees their badges at once, and `#vip-lounge` with its history.
- [ ] A follows the moved text channels without a click; a post by you lights a dot, a mention a count and a sound.
- [ ] You: *Waiting for your OK* lists A for `Moderator-power` and the others; OK with a code. A is asked for
      two-factor codes; once on, A can do what Moderator allows (try a hide).
- [ ] A, in the archive pane: hide A-2, delete A-5. Others no longer see them.
- [ ] On the phone or in a browser as you: the dashboard, the OK list and Undo show, with the card saying the rest
      is on the desktop.

## 6. The move post

- [ ] End screen → Post. The offered text says where to go. It goes to a channel everyone reads, never a private one.
      Check it in Discord.

## 7. Run 2

```sh
node testkit/7-discord-test-guild/setup.mjs change
```

That adds 10 posts each in `#general` and `#bulk` and one thread reply; makes `#new-after-run-1` (open) and
`#new-private-after-run-1` (VIP only); closes `#off-topic` to @everyone; edits the edited post again and deletes the
@everyone post; renames `#emote-test` and the role `No Colour`; gives Moderator *Manage Channels* and a green colour;
adds the emoji `vt_new`; unbans C.

Run 2 in the wizard (*Go on* is gone after Done, so it starts from the token):
- [ ] The dry-run's warning covers channels it cannot tell apart (MOVING.md, "After a stop").
- [ ] `#new-after-run-1` starts on, `#new-private-after-run-1` starts off.
- [ ] `#off-topic` is refused: "Private on Discord now and open here. Give it a gate, then run again."
- [ ] Only the new posts come; nothing doubled; the thread reply lands in its thread.
- [ ] The edited post keeps its run-1 text here; the @everyone post is still here.
- [ ] `#emote-test`'s name here: ______. `No Colour`'s group keeps its name; Moderator's colour turns green.
- [ ] `Moderator-power` gains `voipc:channels`: does A's OK stand, or does it wait again: ______.
- [ ] `vt_new` comes.
- [ ] The end screen says C is no longer banned there; `dc-<C>` stays until *Lift ban*. Lift it (code): C moves to
      *Left out* as held.
- [ ] A-5 stays deleted, A-2 stays hidden.
- [ ] `#leave-me-out` starts left out again.

## 8. Undo

- [ ] Undo run 2 first (run 1's Undo is refused until then), then run 1. Each shows what goes, and takes a code.
- [ ] After both: the moved channels, emotes, groups and A's unopened account (if A had not signed in) are gone;
      your own account and A's opened one stay, without the move's groups.
- [ ] A new run 1 after that: A-5 is still deleted, A-2 still hidden ("What a person deleted stays deleted").

## 9. Clean up

- [ ] Discord: Server Settings → Integrations → the app → Kick. Developer Portal: Bot → Reset Token, keep nothing.
- [ ] Delete `target/discord-test-guild/<server id>.json` and the test server.
- [ ] On the relay: delete the `<database>.before-import-<run>` copies.

## Report

Copy this page, keep the ✓/✗ marks and the blanks filled in, and add screenshots for each ✗. Also the relay's log
lines with `import` or `archive` from the runs, and how long each run took.
