// The ring, and where a person read: what a followed channel can say when the words it means
// are not on this device (`marks-rules.ts`).
//
// The position lives in `uiPrefs`, by the channel's log or name, in the relay's clock. It moves
// with every post, so it is written now and then, and when the app goes.

import { get } from "svelte/store";

import { channels } from "./channels.js";
import { textSeats } from "./rosters.js";
import { scoped } from "./scoped.js";
import { historyKey } from "./history-scope.js";
import { uiPrefs, updateUiPrefs } from "./ui-prefs.js";
import { afterMark, OWN_CLOCK_SLACK_MS } from "../marks-rules.js";
import { stableName } from "../follow-rules.js";
import type { ChannelInfo } from "../types.js";

/**
 * Channels whose row shows a ring. "opened": it had one when opened with nobody left to ask, so
 * the row is plain again and the pane says what it knows until the person looks elsewhere.
 */
export const channelRings = scoped<ReadonlyMap<number, "lit" | "opened">>(() => new Map());

const WRITE_EVERY_MS = 15_000;
let unwritten = new Map<string, Map<string, number>>();
let writeTimer: ReturnType<typeof setTimeout> | null = null;

function readAt(server: string, channel: ChannelInfo): number | undefined {
  const key = historyKey(server);
  const stable = stableName(channel);
  return unwritten.get(key)?.get(stable) ?? get(uiPrefs).read_marks[key]?.[stable];
}

/** What waits goes into the prefs now: from the timer, and when the app goes. */
export function flushMarks(): void {
  if (writeTimer !== null) clearTimeout(writeTimer);
  writeTimer = null;
  if (unwritten.size === 0) return;
  const batch = unwritten;
  unwritten = new Map();
  updateUiPrefs((p) => {
    for (const [key, marks] of batch) p.read_marks[key] = { ...p.read_marks[key], ...Object.fromEntries(marks) };
  });
}

/** They read this far, or their own post stands this far. Never back. */
export function moveRead(server: string, channel: ChannelInfo, at: number): void {
  const before = readAt(server, channel);
  if (before !== undefined && before >= at) return;
  const key = historyKey(server);
  if (!key) return;
  let marks = unwritten.get(key);
  if (!marks) unwritten.set(key, (marks = new Map()));
  marks.set(stableName(channel), at);
  writeTimer ??= setTimeout(flushMarks, WRITE_EVERY_MS);
}

export function lightRing(server: string, channelId: number): void {
  channelRings.of(server).update((m) => (m.get(channelId) === "lit" ? m : new Map(m).set(channelId, "lit")));
  const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
  if (channel) ringsKept(server).add(stableName(channel));
}

/** Rings lit, by a name a reconnect keeps: it drops `channelRings`, as an id is a slot in one
 *  run, and the relay's mark alone can say nothing of a post within `OWN_CLOCK_SLACK_MS` of
 *  where they read. What goes on: `ringBack`. Until something is read, or the server closes. */
const ringsLit = new Map<string, Set<string>>();

function ringsKept(server: string): Set<string> {
  let lit = ringsLit.get(server);
  if (!lit) ringsLit.set(server, (lit = new Set()));
  return lit;
}

/** A channel followed on a new connection: its ring is back if nothing has been read. */
export function ringBack(server: string, channel: ChannelInfo): void {
  if (ringsLit.get(server)?.has(stableName(channel))) lightRing(server, channel.channel_id);
}

/** The server was closed. */
export function forgetRings(server: string): void {
  ringsLit.delete(server);
}

/** A post that will never open here. Where they read stays where it was: it is what brings
 *  the ring back at the next start, and they have read nothing. A first sight has no place to
 *  stay at, so it starts just before this post. */
export function ringForPost(server: string, channelId: number, at: number): void {
  const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
  if (!channel) return;
  if (readAt(server, channel) === undefined) moveRead(server, channel, Math.max(1, at - OWN_CLOCK_SLACK_MS - 1));
  lightRing(server, channelId);
}

/** They read as far as the relay last said anyone wrote, once nothing more can be done. */
function readToLastPost(server: string, channelId: number): void {
  const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
  if (channel) ringsLit.get(server)?.delete(stableName(channel));
  const lastPost = get(textSeats.peek(server)).get(channelId)?.lastPost ?? 0;
  if (channel && lastPost > 0) moveRead(server, channel, lastPost);
}

export function clearRing(server: string, channelId: number): void {
  if (!get(channelRings.peek(server)).has(channelId)) return;
  channelRings.of(server).update((m) => {
    const next = new Map(m);
    next.delete(channelId);
    return next;
  });
  readToLastPost(server, channelId);
}

/** The row goes plain; the pane goes on saying what it knows while it is on screen. */
export function ringOpened(server: string, channelId: number): void {
  channelRings.of(server).update((m) => (m.get(channelId) === "lit" ? new Map(m).set(channelId, "opened") : m));
  readToLastPost(server, channelId);
}

/** Another channel came on screen: nothing more to say about the one before. */
export function dropOpenedRings(server: string, except: number): void {
  channelRings.of(server).update((m) => {
    const next = new Map([...m].filter(([id, state]) => state === "lit" || id === except));
    return next.size === m.size ? m : next;
  });
}

/** A mark from the relay: someone wrote there at `lastPost`. */
export function noteLastPost(server: string, channelId: number, lastPost: number): void {
  const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
  if (!channel) return;
  const { read, ring } = afterMark(readAt(server, channel), lastPost);
  if (read !== undefined && readAt(server, channel) === undefined) moveRead(server, channel, read);
  if (ring) lightRing(server, channelId);
}
