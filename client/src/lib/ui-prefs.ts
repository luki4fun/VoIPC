// The shape of everything the UI remembers about how it looks, and the one
// function that turns whatever was on disk into something safe to render from.
//
// Pure module — no stores, no invoke — so ui-prefs.test.ts can load it under
// Node's own test runner. The store that owns the live value and saves it is
// stores/ui-prefs.ts.
//
// This is the only setting in the app persisted as a blob rather than through a
// command per field; the argument for that is on the `ui_prefs` field in
// client/src-tauri/src/config.rs, and it turns on nothing else owning it.

import { DEFAULT_PALETTE_ID, migratePaletteId, TOKENS, type TokenName } from "./theme.ts";

export type LayoutId = "classic" | "modern" | "stage";
export type Density = "cosy" | "compact";

/**
 * What this build's first-run layout question covers.
 *
 * A version rather than a bool, for the same reason `audio_setup_version` is
 * one: a later release that adds a third layout can ask again, and it cannot be
 * derived from `layout`, which reads "modern" whether or not anybody chose it.
 * 2: Stage arrived (2026-10-26), so everybody is offered the choice once more.
 */
export const LAYOUT_PICKER_VERSION = 2;

export interface PanelPrefs {
  /** Channel sidebar width in px. */
  sidebar: number;
  /** Member list width in px. */
  members: number;
  sidebar_open: boolean;
  members_open: boolean;
}

/** Where the chat sits beside a screen share. */
export type StreamChatSplit = "side" | "below";

/** The chat docked to a screen share (the stream view), per layout. */
export interface StreamChatPrefs {
  open: boolean;
  split: StreamChatSplit;
  /** Chat width beside the stream, px. */
  width: number;
  /** Chat height below the stream, px. */
  height: number;
}

export interface UiPrefs {
  layout: LayoutId;
  /** Which layout question this user has answered; 0 means never. */
  layout_asked_version: number;
  palette: string;
  /**
   * Whether somebody picked `palette` in Settings, rather than the app picking
   * it for a new install. Recorded since 2026-10-26, when the default palette
   * changed: a file written before then carries no flag and reads as chosen,
   * because nobody can tell its stored palette from a default any more. What
   * the flag buys is the next change of default — it can move the people who
   * never chose, and only them.
   */
  palette_chosen: boolean;
  palette_overrides: Partial<Record<TokenName, string>>;
  density: Density;
  /** Chat message font size in px. */
  chat_font_size: number;
  /** Whole-UI zoom, 1 = unscaled. */
  zoom: number;
  /** Remembered per layout: the two shells want very different widths. */
  panels: Record<LayoutId, PanelPrefs>;
  /** Per layout too: the classic one has always shown it, below. */
  stream_chat: Record<LayoutId, StreamChatPrefs>;
  /** The floating preview of your own share. Off once you hide it. */
  share_preview: boolean;
  /**
   * Busy answers to one message gather into a thread of their own
   * (thread-rules.ts `threadView`). Answers sent into a thread go there either way.
   */
  group_threads: boolean;
  /**
   * The start of the last message under each direct conversation in the
   * sidebar, with how long ago. Off unless chosen: anyone who sees the screen
   * (a screen share) reads it too. A message with a timer never shows.
   */
  dm_previews: boolean;
  /**
   * Text channels the user walked out of, per server (`"host:port"` → names).
   *
   * A server can ask every client to join a text channel on connect
   * (`auto_join`), which would otherwise undo leaving it at the next
   * reconnect. This is the client's memory of that decision, and the reason
   * the server never joins anybody itself. By name rather than id, because a
   * user-created channel's id is not stable across a server restart.
   */
  left_text_channels: Record<string, string[]>;
  /**
   * Destruction timers the user set on direct messages, in seconds, keyed
   * `"host:port/peer name"` — 0 or absent is no timer.
   *
   * A channel's timer is the channel's: the server advertises it and everyone
   * in the room sees the same number. A direct message has no such object, so
   * this is the sender's own answer, and it travels with each message they
   * write. What arrives from the other side carries theirs, and the shorter of
   * the two wins wherever a copy is stored (`expiryFor`).
   */
  dm_timers: Record<string, number>;
  /**
   * Servers (`"host:port"`) on which the user confirmed being 18 or older, so
   * their channels marked 18+ join and show without asking again.
   *
   * Per server, because it is each server's channels the answer was about.
   * The server is never told: the flag on a channel is all it carries.
   */
  nsfw_ok: string[];
  /**
   * Whether a loaded video or sound plays inside VoIPC, through the system's
   * own decoders; null is this platform's default (media.ts `playsMedia`).
   */
  play_media: boolean | null;
  /** Stickers others send are shown (else named only). */
  show_stickers: boolean;
  /** Moving emotes and stickers: always, on hover, or never (their first
   *  frame). Reduced motion on the system means never, whatever this says. */
  animate_emotes: "always" | "hover" | "never";
  /**
   * Servers (`"host:port"`) whose emotes and stickers download on mobile data
   * without asking ("Always on this server" in that question). Settings →
   * Files lists them, each with "Ask again".
   */
  emotes_mobile_ok: string[];
}

/** Bounds. A width outside these is a panel you cannot get back by dragging. */
export const SIDEBAR_MIN = 160;
export const SIDEBAR_MAX = 480;
export const MEMBERS_MIN = 140;
export const MEMBERS_MAX = 480;
export const CHAT_FONT_MIN = 11;
export const CHAT_FONT_MAX = 20;
export const ZOOM_MIN = 0.8;
export const ZOOM_MAX = 1.5;
export const STREAM_CHAT_WIDTH_MIN = 240;
export const STREAM_CHAT_WIDTH_MAX = 800;
export const STREAM_CHAT_HEIGHT_MIN = 120;
export const STREAM_CHAT_HEIGHT_MAX = 720;

export function defaultPanels(layout: LayoutId): PanelPrefs {
  // The classic defaults are the widths that were hard-coded in ChannelList
  // and UserList before they became variables, so nothing moves for anyone who
  // never touches this. The modern sidebars are wider because their rows carry
  // nested members and avatars.
  // Stage's second panel is the chat drawer rather than a member list: the
  // people are the centre of that layout. Closed until asked for, wide enough
  // to read in when it is.
  if (layout === "stage") return { sidebar: 240, members: 360, sidebar_open: true, members_open: false };
  return layout === "modern"
    ? { sidebar: 240, members: 240, sidebar_open: true, members_open: true }
    : { sidebar: 220, members: 180, sidebar_open: true, members_open: true };
}

export function defaultStreamChat(layout: LayoutId): StreamChatPrefs {
  // Modern opens a share full-window and the chat is asked for with a toggle;
  // classic has shown it under the viewer, 280 px tall, since before either.
  return layout === "modern" || layout === "stage"
    ? { open: false, split: "side", width: 360, height: 280 }
    : { open: true, split: "below", width: 360, height: 280 };
}

export function defaultUiPrefs(): UiPrefs {
  return {
    layout: "modern",
    layout_asked_version: 0,
    palette: DEFAULT_PALETTE_ID,
    palette_chosen: false,
    palette_overrides: {},
    density: "cosy",
    chat_font_size: 13,
    zoom: 1,
    panels: {
      classic: defaultPanels("classic"),
      modern: defaultPanels("modern"),
      stage: defaultPanels("stage"),
    },
    stream_chat: {
      classic: defaultStreamChat("classic"),
      modern: defaultStreamChat("modern"),
      stage: defaultStreamChat("stage"),
    },
    share_preview: true,
    group_threads: true,
    dm_previews: false,
    left_text_channels: {},
    dm_timers: {},
    nsfw_ok: [],
    play_media: null,
    show_stickers: true,
    animate_emotes: "always",
    emotes_mobile_ok: [],
  };
}

/** How many servers, and how many channels each, this remembers. */
const LEFT_MAX_SERVERS = 50;
const LEFT_MAX_PER_SERVER = 100;

// Both caps keep the *end* of the list, because `rememberLeft` appends: the
// newest leave is the one the user just made, and dropping that is how somebody
// walks out of a channel and is put back in it on the next connect — which is
// the one thing this field exists to prevent.
function leftTextChannels(raw: unknown): Record<string, string[]> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, string[]> = {};
  for (const [server, names] of Object.entries(raw as Record<string, unknown>).slice(
    -LEFT_MAX_SERVERS,
  )) {
    if (!Array.isArray(names)) continue;
    const list = names.filter((n): n is string => typeof n === "string" && n !== "");
    if (list.length > 0) out[server] = [...new Set(list)].slice(-LEFT_MAX_PER_SERVER);
  }
  return out;
}

/** How many conversations' timers this remembers, newest kept. */
const DM_TIMER_MAX = 500;
/** The same 30 days a message's own timer is bounded to (chat-rules.ts). */
const DM_TIMER_MAX_SECS = 30 * 24 * 60 * 60;

function dmTimers(raw: unknown): Record<string, number> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, number> = {};
  for (const [key, secs] of Object.entries(raw as Record<string, unknown>).slice(-DM_TIMER_MAX)) {
    const n = typeof secs === "number" ? Math.floor(secs) : Number.NaN;
    if (Number.isFinite(n) && n > 0) out[key] = Math.min(n, DM_TIMER_MAX_SECS);
  }
  return out;
}

/** How many servers' 18+ consent this remembers, newest kept. */
const NSFW_OK_MAX = 200;

/** A list of servers (`"host:port"`), as `nsfw_ok` and `emotes_mobile_ok` keep
 *  them: strings only, no blanks, no repeats, the newest few hundred. */
function nsfwOk(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const list = raw.filter((k): k is string => typeof k === "string" && k !== "");
  return [...new Set(list)].slice(-NSFW_OK_MAX);
}

function clamp(value: unknown, lo: number, hi: number, fallback: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(hi, Math.max(lo, n));
}

function bool(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

/**
 * A stored layout id, including the names these layouts used to have.
 *
 * The modern one was `discord` until 0.9.0, and a rename must not cost anybody
 * the layout they chose — so the old spelling still reads, and only the new one
 * is ever written. `legacy` is read for the same reason: it is what this branch
 * briefly called the classic layout before the name went back. Anything else
 * falls back rather than throwing: the file is hand-editable, and in the
 * browser it is localStorage.
 */
function layoutId(raw: unknown, fallback: LayoutId): LayoutId {
  if (raw === "modern" || raw === "discord") return "modern";
  if (raw === "classic" || raw === "legacy") return "classic";
  if (raw === "stage") return "stage";
  return fallback;
}

function panels(raw: unknown, layout: LayoutId): PanelPrefs {
  const d = defaultPanels(layout);
  if (!raw || typeof raw !== "object") return d;
  const r = raw as Record<string, unknown>;
  return {
    sidebar: clamp(r.sidebar, SIDEBAR_MIN, SIDEBAR_MAX, d.sidebar),
    members: clamp(r.members, MEMBERS_MIN, MEMBERS_MAX, d.members),
    sidebar_open: bool(r.sidebar_open, d.sidebar_open),
    members_open: bool(r.members_open, d.members_open),
  };
}

function streamChat(raw: unknown, layout: LayoutId): StreamChatPrefs {
  const d = defaultStreamChat(layout);
  if (!raw || typeof raw !== "object") return d;
  const r = raw as Record<string, unknown>;
  return {
    open: bool(r.open, d.open),
    split: r.split === "side" || r.split === "below" ? r.split : d.split,
    width: clamp(r.width, STREAM_CHAT_WIDTH_MIN, STREAM_CHAT_WIDTH_MAX, d.width),
    height: clamp(r.height, STREAM_CHAT_HEIGHT_MIN, STREAM_CHAT_HEIGHT_MAX, d.height),
  };
}

/**
 * Whatever came out of settings.json, made safe.
 *
 * Nothing in here throws. The file can be hand-edited, can have been written by
 * a newer build, and — in the browser, where it lives in localStorage — can
 * have been edited by anyone with the devtools open. A bad value must cost the
 * user that one preference, never the app: losing your palette is annoying,
 * a client that will not start because a number was a string is not.
 *
 * Unknown keys are deliberately *not* carried through. They would be a second,
 * invisible copy of state that nothing validates, and the round-trip that keeps
 * a newer build's settings intact happens in stores/ui-prefs.ts, which merges
 * the raw object rather than this one.
 */
export function sanitizeUiPrefs(raw: unknown): UiPrefs {
  const d = defaultUiPrefs();
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return d;
  const r = raw as Record<string, unknown>;

  const overrides: Partial<Record<TokenName, string>> = {};
  if (r.palette_overrides && typeof r.palette_overrides === "object") {
    const given = r.palette_overrides as Record<string, unknown>;
    for (const token of TOKENS) {
      const value = given[token];
      // A token this build does not know would be written to the document
      // as-is; a typo in a hand-edited file should not become a live property.
      if (typeof value === "string" && value.trim() !== "") overrides[token] = value;
    }
  }

  const p = r.panels && typeof r.panels === "object" ? (r.panels as Record<string, unknown>) : {};
  const sc =
    r.stream_chat && typeof r.stream_chat === "object"
      ? (r.stream_chat as Record<string, unknown>)
      : {};

  return {
    layout: layoutId(r.layout, d.layout),
    layout_asked_version: clamp(r.layout_asked_version, 0, 1e6, 0),
    // A palette id from a newer build resolves to the default at render time
    // (paletteById), but keep the id: downgrading and upgrading again should
    // not silently forget which palette somebody chose.
    palette:
      typeof r.palette === "string" && r.palette !== ""
        ? migratePaletteId(r.palette)
        : d.palette,
    // Absent means a file from before the flag existed: its palette stands as
    // chosen (the 1.x rule, a stored choice is never overwritten)
    palette_chosen:
      typeof r.palette === "string" && r.palette !== "" ? r.palette_chosen !== false : false,
    palette_overrides: overrides,
    density: r.density === "compact" ? "compact" : "cosy",
    chat_font_size: clamp(r.chat_font_size, CHAT_FONT_MIN, CHAT_FONT_MAX, d.chat_font_size),
    zoom: clamp(r.zoom, ZOOM_MIN, ZOOM_MAX, d.zoom),
    // `p.discord` is what a pre-0.9.0 file calls the modern one, and `p.legacy`
    // what this branch called the classic one for an afternoon; a sidebar
    // somebody dragged keeps its width across both renames.
    panels: {
      classic: panels(p.classic ?? p.legacy, "classic"),
      modern: panels(p.modern ?? p.discord, "modern"),
      stage: panels(p.stage, "stage"),
    },
    stream_chat: {
      classic: streamChat(sc.classic, "classic"),
      modern: streamChat(sc.modern, "modern"),
      stage: streamChat(sc.stage, "stage"),
    },
    share_preview: bool(r.share_preview, d.share_preview),
    group_threads: bool(r.group_threads, d.group_threads),
    dm_previews: bool(r.dm_previews, d.dm_previews),
    left_text_channels: leftTextChannels(r.left_text_channels),
    dm_timers: dmTimers(r.dm_timers),
    nsfw_ok: nsfwOk(r.nsfw_ok),
    play_media: typeof r.play_media === "boolean" ? r.play_media : null,
    show_stickers: bool(r.show_stickers, d.show_stickers),
    animate_emotes: r.animate_emotes === "hover" || r.animate_emotes === "never" ? r.animate_emotes : "always",
    emotes_mobile_ok: nsfwOk(r.emotes_mobile_ok),
  };
}
