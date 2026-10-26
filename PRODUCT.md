# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

One Svelte 5 front end runs everywhere: in Tauri 2 desktop shells (Linux WebKitGTK, Windows
WebView2), in any modern browser (served by the relay itself), and inside the Android app's
WebView. The Android shell still owes the platform its guarantees: system Back, edge-to-edge
insets, the keyboard (IME) inset, 48 dp touch targets.

## Users

- **Members:** small private groups — friends, gaming crews, role-play communities driving
  positions through the game SDK. They want a Discord or TeamSpeak replacement they do not have to
  think about: install the app or open the browser client, type a name, talk.
- **The operator:** one technical person per group who runs the relay (a single static binary)
  and hands out the address or an invite link. Often also a member.

## Product Purpose

Voice, screen sharing and chat on a server the group runs itself, end-to-end encrypted, with a
relay that by default stores nothing. Voice and screen share are the critical features and must
never break on Linux, Windows or Android; chat matters but is secondary. Success is a group that
moves over and stops noticing the tool.

## Positioning

The relay cannot read anything it forwards — Signal Protocol for messages, AES-256-GCM for voice,
video and positions — and without accounts it keeps nothing past a restart. It is open source
(MIT), self-hosted, needs no account unless the operator turns accounts on, and the browser client
carries the same encryption. Proximity chat with a game SDK is the open alternative to the
TeamSpeak plugins RP servers install today.

## Operating Context

- Long sessions in voice while gaming, working or hanging out; the window often sits behind a game
  or beside an editor. Push-to-talk works system-wide on the desktop.
- Watching a friend's screen share, on a desktop or on a phone (Android is view-only for sharing).
- Several servers open at once; text channels are subscriptions, voice is one channel at a time.
- Joining is the riskiest moment: a host, a port, a name, sometimes a self-signed certificate
  (pinned on first use).

## Capabilities and Constraints

- Three layout presets share all behaviour (stores and dialogs mounted once in `App.svelte`);
  only arrangement differs per layout. Modern and Classic exist; Stage is being added (2026-10-26).
- Palettes are token sets in `client/src/lib/theme.ts`, each held to WCAG AA by unit tests; every
  token is user-editable in Settings → Appearance.
- One live screen-share decode at a time per client; other shares can only be offered, not shown
  live.
- The version string equals protocol compatibility (the relay compares it for equality); a
  headline feature is a minor bump.
- 1.x rule: stored user data and choices are never silently overwritten by an upgrade.
- Terminology: channel (voice or text), server, relay (the binary), push to talk, voice
  activation, share / watch, poke, invite, chat history.

## Brand Commitments

- Name: VoIPC. Logo: a mint shield with a signal glyph and padlock on charcoal
  (`client/src-tauri/icons/`).
- Inspired by Discord, never an imitation: Discord's name, palette or trade dress must not appear
  in the product (owner rule, 2026-09-17).
- Voice: plain, specific and honest — states limits ("not audited", "macOS is not supported"),
  no hype. "Built with Rust, Svelte, and paranoia."
- No analytics, no telemetry, no cookies — on the site as in the app.

## Evidence on Hand

- The app itself and `tools/screenshots.mjs`, which captures every layout and palette at desktop,
  tablet and phone widths against a scratch relay.
- Specs, threat model and docs in `README.md`, `docs/`, `SECURITY.md`, `CHANGELOG.md`.
- No testimonials, user counts, press or independent security audit exist; never invent them.

## Product Principles

1. Voice and screen share before everything; nothing may get between a person and talking.
2. The relay knows nothing; the user is protected from the operator and from moderators too.
3. Easy to set up, easy to use: a friend who is not technical must be able to join unaided.
4. Honest by default: say what is stored, what is not, and what does not work yet.
5. Familiar where it helps, VoIPC's own where it counts.

## Accessibility & Inclusion

WCAG 2.2 AA for every palette and both pointer types: keyboard-complete, screen-reader names and
states, 44 px targets on touch, reduced motion honoured, text never below 11 px.
