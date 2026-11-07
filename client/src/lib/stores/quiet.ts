// Quiet mode, per device and server: only the channels a person picks arrive here, and the rest
// are followed with no posts and no keys, showing a ring when someone wrote (`follow-rules.ts`).
//
// A local pref, never the vault, never a server setting: only the person can turn it on. It
// shows the relay which channels they picked and when they open another, which the screen says.

import { get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { activeTextChannelId, joinedTextChannelIds } from "./chat.js";
import { channels } from "./channels.js";
import { serverKey, serverAddress } from "./connection.js";
import { metered } from "./emotes.js";
import { scoped } from "./scoped.js";
import { setSweepQuiet } from "./sweep.js";
import { uiPrefs, updateUiPrefs } from "./ui-prefs.js";
import { quietOn, quietSet, stableName, type QuietMode } from "../follow-rules.js";
import type { ChannelInfo } from "../types.js";

/** Followed quietly now. */
export const quietChannels = scoped<ReadonlySet<number>>(() => new Set());

/** Off screen for this long, a channel the mode wants quiet goes quiet, with no rotation. */
const BACK_TO_QUIET_MS = 10 * 60_000;
const LOOK_EVERY_MS = 60_000;

/** Channels the mode wants quiet, kept whole as they are or were on screen, and when last. */
const openNow = new Map<string, { at: Map<number, number>; timer: ReturnType<typeof setInterval> }>();

function modeOf(server: string): QuietMode {
  return get(uiPrefs).quiet_mode[serverKey(server)]?.mode ?? "off";
}

/** The text channel on screen, if this server is. */
function onScreen(server: string): number | null {
  return get(serverAddress) === server ? get(activeTextChannelId.peek(server)) : null;
}

/** On screen now: `lookBack` lets it go once it has been away for its while. */
function keepOpen(server: string, channelId: number): void {
  let open = openNow.get(server);
  if (!open) {
    open = { at: new Map(), timer: setInterval(() => lookBack(server), LOOK_EVERY_MS) };
    openNow.set(server, open);
  }
  open.at.set(channelId, Date.now());
}

function wanted(server: string, list: readonly ChannelInfo[]): Set<number> {
  const prefs = get(uiPrefs).quiet_mode[serverKey(server)];
  const quiet = quietSet(list, prefs?.whole ?? [], quietOn(prefs?.mode ?? "off", metered()));
  // The channel someone is reading never goes to sleep under them
  const shown = onScreen(server);
  if (shown !== null && quiet.has(shown)) keepOpen(server, shown);
  for (const id of openNow.get(server)?.at.keys() ?? []) quiet.delete(id);
  return quiet;
}

/** Of the channels about to be followed, those that go in quiet. */
export function quietOf(server: string, ids: readonly number[]): number[] {
  const list = get(channels.peek(server)).filter((c) => ids.includes(c.channel_id));
  const quiet = wanted(server, list);
  quietChannels.of(server).update((had) => new Set([...had, ...quiet]));
  setSweepQuiet(server, get(quietChannels.peek(server)));
  return ids.filter((id) => quiet.has(id));
}

/** The mode, the picks or the network changed: what is followed goes where it should be. */
export function applyQuiet(server: string): void {
  const joined = get(joinedTextChannelIds.peek(server));
  const list = get(channels.peek(server)).filter((c) => c.text && joined.has(c.channel_id));
  const want = wanted(server, list);
  const had = get(quietChannels.peek(server));
  const goQuiet = [...want].filter((id) => !had.has(id));
  const goWhole = [...had].filter((id) => !want.has(id));
  quietChannels.of(server).set(want);
  setSweepQuiet(server, want);
  if (goQuiet.length > 0) void invoke("set_quiet", { server, channels: goQuiet, quiet: true }).catch(() => {});
  if (goWhole.length > 0) void invoke("set_quiet", { server, channels: goWhole, quiet: false }).catch(() => {});
}

export function setQuietMode(server: string, mode: QuietMode): void {
  const key = serverKey(server);
  if (!key) return;
  updateUiPrefs((p) => {
    // What this device opened is where to start: nobody should have to pick from nothing
    const whole = p.quiet_mode[key]?.whole ?? p.opened_channels[key] ?? [];
    p.quiet_mode[key] = { mode, whole };
  });
  applyQuiet(server);
}

export function setWholeHere(server: string, channel: ChannelInfo, whole: boolean): void {
  const key = serverKey(server);
  if (!key) return;
  const stable = stableName(channel);
  updateUiPrefs((p) => {
    const now = p.quiet_mode[key] ?? { mode: "off" as QuietMode, whole: [] };
    const rest = now.whole.filter((n) => n !== stable && n !== channel.name);
    p.quiet_mode[key] = { mode: now.mode, whole: whole ? [...rest, stable] : rest };
  });
  applyQuiet(server);
}

function lookBack(server: string): void {
  const open = openNow.get(server);
  if (!open) return;
  const active = onScreen(server);
  const now = Date.now();
  if (active !== null && open.at.has(active)) open.at.set(active, now);
  let changed = false;
  for (const [id, at] of open.at) {
    if (now - at < BACK_TO_QUIET_MS) continue;
    open.at.delete(id);
    changed = true;
  }
  if (open.at.size === 0) {
    clearInterval(open.timer);
    openNow.delete(server);
  }
  if (changed) applyQuiet(server);
}

/**
 * A quiet channel came on screen. Writers key this person at their next post, naming them on
 * the writer's device as anyone, and it goes quiet again when they have moved on.
 */
export function openedQuiet(server: string, channelId: number): void {
  if (!get(quietChannels.peek(server)).has(channelId)) return;
  keepOpen(server, channelId);
  applyQuiet(server);
  const log = get(channels.peek(server)).find((c) => c.channel_id === channelId)?.log;
  if (log) invoke("account_read_now", { server, conv: log }).catch(() => {}); // a guest keeps none
}

/** A connection's quiet goes with it; what was picked is in the prefs. */
export function clearQuiet(server: string): void {
  const open = openNow.get(server);
  if (open) clearInterval(open.timer);
  openNow.delete(server);
}

/** How long a network has to last before "on mobile data" acts on it: every frame it costs is
 *  a name for the relay, and a phone at the edge of Wi-Fi goes back and forth. */
const NETWORK_SETTLES_MS = 2 * 60_000;
let settling: ReturnType<typeof setTimeout> | null = null;

/** The mobile data mode goes by the network: called when that changes. */
export function networkChanged(servers: () => readonly string[]): void {
  if (settling !== null) clearTimeout(settling);
  settling = setTimeout(() => {
    settling = null;
    for (const server of servers()) if (modeOf(server) === "mobile") applyQuiet(server);
  }, NETWORK_SETTLES_MS);
}
