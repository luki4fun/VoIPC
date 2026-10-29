---
name: VoIPC
description: Voice, screen sharing and chat on a server you run — charcoal and one mint that means "live".
colors:
  charcoal-chat: "#1c1f24"
  charcoal-panel: "#16181d"
  charcoal-deep: "#0f1114"
  charcoal-raised: "#262a31"
  ink-primary: "#e3e6ea"
  ink-secondary: "#a3aab4"
  ink-muted: "#8b939e"
  mint: "#3ddbb0"
  mint-raised: "#5fe6c2"
  on-mint: "#06231b"
  danger: "#f2555a"
  warning: "#f2b84b"
  hairline: "#2a2e36"
  day-surface: "#ffffff"
  day-panel: "#f3f5f6"
  day-ink: "#0e1114"
  day-mint: "#0b7a5f"
typography:
  micro:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 600
    letterSpacing: "0.02em"
  small:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 400
  body:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 600
  title:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 700
  site-display:
    fontFamily: "Barlow Semi Condensed, system-ui, sans-serif"
    fontSize: "3.6rem"
    fontWeight: 700
    lineHeight: 1
  site-heading:
    fontFamily: "Barlow Semi Condensed, system-ui, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 700
  site-label:
    fontFamily: "Barlow Semi Condensed, system-ui, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 600
    letterSpacing: "0.08em"
  site-body:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.6
  site-small:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
  site-lead:
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 400
  site-data:
    fontFamily: "JetBrains Mono, ui-monospace, Consolas, monospace"
    fontSize: "0.875rem"
    fontWeight: 400
rounded:
  sm: "4px"
  md: "8px"
  lg: "12px"
  pill: "999px"
spacing:
  "1": "4px"
  "2": "8px"
  "3": "12px"
  "4": "16px"
  "6": "24px"
  "8": "32px"
components:
  button-primary:
    backgroundColor: "{colors.mint}"
    textColor: "{colors.on-mint}"
    rounded: "{rounded.sm}"
    padding: "8px 16px"
    height: "36px"
  button-primary-hover:
    backgroundColor: "{colors.mint-raised}"
  button-secondary:
    backgroundColor: "{colors.charcoal-deep}"
    textColor: "{colors.ink-primary}"
    rounded: "{rounded.sm}"
    padding: "8px 16px"
  button-danger:
    backgroundColor: "{colors.danger}"
    textColor: "{colors.charcoal-deep}"
    rounded: "{rounded.sm}"
  row-selected:
    backgroundColor: "{colors.charcoal-raised}"
    textColor: "{colors.ink-primary}"
    rounded: "{rounded.sm}"
---

# Design System: VoIPC

## Overview

A working tool for people who are in a call for hours: the window sits beside a game or an editor, and the person glances at it to see who is talking, who is sharing, and what was said. The surface is charcoal and quiet; colour is spent on one meaning only. Familiar shapes on purpose — a server rail, a channel list, a chat, a member list — because people arrive from Discord and TeamSpeak and should know where everything is before they notice the paint. What is VoIPC's own is the palette, taken from the logo (a mint shield on charcoal, `client/src-tauri/icons/`), and the rule it carries.

Every palette, including the user's own edits in Settings → Appearance, is a set of CSS custom properties written by `client/src/lib/theme.ts` and held to WCAG AA in `theme.test.ts`. The values above are **VoIPC night**, the default; **VoIPC day** is its light twin. Navy, Slate dark/light and AMOLED black remain selectable, and a stored choice is never repainted by an upgrade.

Three layouts share every behaviour and differ only in arrangement: **Modern** (rail, channels with people in them, chat, members), **Classic** (channels, chat and members in columns, voice and status bars along the bottom) and **Stage** (the call in the centre). Dialogs, menus, stores and keyboard handling are mounted once, in `App.svelte`; a layout owns rows and bars, never logic.

## Colors

### Primary

**Mint** is *live*: somebody talking (the ring around their avatar), the talk button while held, a share going out, the connected state, and the primary action of a dialog. Text and icons on it use **On-mint**, a deep green-black — white on this mint is under 2:1. On the day palette the same role is **Day mint**, deep enough for white text and to read as text itself.

### Neutral

Charcoal with a little blue in it. The chat is the lighter surface (**Charcoal chat**); sidebars sit behind it (**Charcoal panel**); the rail and fields are recessed (**Charcoal deep**); a selected or hovered row rises to **Charcoal raised**. Text steps down from **Ink primary** to **Ink secondary** to **Ink muted** — muted is the dimmed state (a channel you left, somebody out of earshot) and it still clears 4.5:1.

### Named Rules

**The Mint Means Live Rule.** Mint marks what is happening now or the one thing a dialog is for. A selected row is raised charcoal, never mint, so a selected channel and a talking face never compete. Settings are ink too: an active tab, a chosen card, a toggle that is on (`.icon-btn.on`: raised, ringed in `--text-muted`), a ticked box and a slider's fill (`--control-fill`). Unread counts are ink badges. Headings, borders, links and decoration never use it.

**The Flat Mint Rule.** No glow, no neon edge, no gradient. Mint is a flat fill or a 2px ring.

**The Ink-on-Fill Rule.** Anything on a filled control takes its palette's on-colour (`--on-accent`, `--on-danger`, `--on-success`, `--on-warning`), never a hard-coded white. A palette that cannot clear 4.5:1 there does not ship.

**The Code Colours Rule.** Code in a message is coloured from five palette tokens (`--code-keyword`, `--code-string`, `--code-comment`, `--code-number`, `--code-fn`) on `--bg-tertiary`, each at 4.5:1 or better (`theme.test.ts`). They are never the live mint and never danger red, so code never reads as live or as an error. Highlighting quotes, mentions and the jump to a message is ink too: a tint of `--text-primary`, never a colour.

## Typography

One system face (`system-ui`): the desktop's own UI font on Linux and Windows, Roboto on Android. Product type, not display type — a tight rem scale (`--fs-micro` 11px through `--fs-2xl` 20px) that the whole-UI zoom scales with.

### Hierarchy

- **Title** (700, 18px): dialog and panel titles, in ink, not mint.
- **Label** (600, 14px): channel header, section headings in dialogs.
- **Body** (400, 13px; the chat itself follows the reader's chat size, 11–20px): messages, rows, descriptions.
- **Small** (400, 12px): hints, timestamps, status.
- **Micro** (600, 11px, uppercase, lightly tracked): sidebar group labels only.
- **Code** (`ui-monospace, "Cascadia Mono", Consolas, monospace` at 0.92em): inline code and fenced blocks in messages. The app ships no font of its own for it.

### Named Rules

**The Floor Rule.** Nothing anybody reads is under 12px; 11px is for uppercase group labels and badges only.

**The Owner's Case Rule.** A channel's name is shown as its owner wrote it — never uppercased, never with `#` on a voice channel.

## Layout

Fixed rem scale, 4px spacing grid (`--sp-1` … `--sp-8`). Responsiveness is structural and driven by the shell's own width (container queries), so the phone shape also appears in a narrow desktop window:

- **Wide** (over 1100px): rail, sidebar, chat, members at their remembered widths.
- **Medium** (721–1100px): the side panels give way to the chat (sidebar ≤ 26%, members ≤ 22% of the width).
- **Narrow** (720px and under): Modern becomes three panes on a track — channel drawer, chat, member drawer — dragged with a thumb; Classic becomes one column with a tab bar.

Safe-area insets are respected everywhere (`env(safe-area-inset-*)`), heights use `dvh`, and on Android the content view is padded by the keyboard so the composer is never under it. Layers are one list in `app.css` (`--z-pane` … `--z-toast`): the phone's talk button sits over full-window activities and under every dialog; toasts are over everything.

## Elevation & Depth

Depth is tone first: recessed (deep), base (panel), content (chat), raised (hover/selected). Shadows only on things that float — menus (`--shadow-menu`) and dialogs (`--shadow-dialog`) — and a scrim (`--scrim`) behind every modal. Light palettes get their own, much softer shadows; a shadow that reads on charcoal is a bruise on white.

## Shapes

Gently rounded and consistent: 4px on buttons, rows and fields; 8px on dialogs and cards; 12px on the rail's server tiles; pills only for small status badges and the jump-to-latest button. Avatars are circles.

## Components

### Buttons

Four kinds, one vocabulary (`.btn` plus `btn-primary`, `btn-secondary`, `btn-danger`, `btn-danger-outline`, `btn-ghost` in `app.css`): primary is the action a dialog exists for, secondary the other way out, danger destroys something, the outline danger destroys something that is not the dialog's point. At least 36px tall for a mouse and 44px for a finger (`--hit`). Labels are verbs in sentence case ("Clear all history", "Stop watching"), never "OK".

### Inputs / Fields

Fields show focus with their border in the focus colour; sliders, checkboxes and anything without a border show the 2px focus ring. Errors sit under the field, in danger, announced (`role="alert"`) and tied to it.

### Navigation

The server rail: 48px tiles with initials in their own legible ink, a pill marking the active server, a dot for unread. Context menus everywhere are the shared `use:menu` (roles, arrows, Escape, focus back); dialogs are the shared `use:dialog`. Both are layers on the back stack, so Android's Back closes the topmost one.

### Talk button

The phone's push-to-talk: a wide button in the thumb zone, held with any pointer (captured, so a sliding thumb keeps it), Space or Enter, or toggled by a screen reader's double tap. Mint while it is open.

### Confirmation

One dialog for every destructive or trust-weakening action (`confirmAction`): it names exactly what goes and where, Cancel has the focus, the confirm button says the verb.

### Website (server browser)

The project site (`website/`) is a Persuade surface in the same world: VoIPC night, mint for live and Join only. It is drawn as one game-server browser window — a filter-tab navigation, a server list whose selected row is "your" server with a live ping and the Join button, the server's info as tabs, its security facts as server rules (key, value, meaning), a compare list and a clients list, the relay's console, a status bar. Its own faces are self-hosted from `website/fonts/` (OFL): **Barlow Semi Condensed** for the browser's headings, tabs and labels, **JetBrains Mono** for data only — server names, slots, ping, rule keys, commands. Body copy stays in the system face. The direction and its contract live in `.impeccable/surfaces/website-index-html.md`; its screenshots come from `tools/screenshots.mjs --website`.

## Do's and Don'ts

### Do:
- **Do** use the tokens — colour, type, space, radius, layer, motion — before writing a number.
- **Do** put text on fills in the palette's on-colour, and add the pair to `CONTRAST_PAIRS` when you add a fill.
- **Do** keep every behaviour in shared stores and actions; a layout only arranges.
- **Do** give icon-only buttons a name and toggles their `aria-pressed`, and make every touch target 44px under a coarse pointer.
- **Do** keep motion to state changes, 120–200ms (`--dur-fast`, `--dur-base`); reduced motion sets them to zero.

### Don't:
- **Don't** use mint for anything that is not live or the dialog's primary action.
- **Don't** hard-code `white`, a status hex, a shadow or a z-index in a component.
- **Don't** hide an action until hover: keyboard focus and a finger need it too.
- **Don't** reproduce Discord's palette, names or trade dress (owner rule): inspired by, never an imitation.
- **Don't** shout: no uppercase names, no tracked capitals beyond group labels.
