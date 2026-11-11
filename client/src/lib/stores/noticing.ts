// What a writer's device says about who it lets read, in the channels where that matters: a
// gate, or joined by hand. In an open channel anyone on the server may read, and nothing
// watches. The relay decides who is in a channel; each writer's device names each reader it
// hands a key to, once ever, so nobody is added without its writer seeing the name.

import { get } from "svelte/store";

import { addChannelMessage } from "./chat.js";
import { accountHex } from "./account.js";
import { channels } from "./channels.js";
import { serverKey } from "./connection.js";
import { historyKey } from "./history-scope.js";
import { textSeats } from "./rosters.js";
import { uiPrefs, updateUiPrefs } from "./ui-prefs.js";
import { goesByList, readersLine, stableName } from "../follow-rules.js";
import { shortName } from "../username.js";
import type { ChannelInfo } from "../types.js";

export interface NamedReader {
  user_id?: number;
  account?: number[] | null;
  name: string;
}

/** A line per minute per channel, the first at once. */
const MERGE_MS = 60_000;

interface Waiting {
  names: Map<string, string>;
  timer: ReturnType<typeof setTimeout> | null;
  lastAt: number;
}

const waiting = new Map<string, Waiting>();

const identityOf = (r: NamedReader) => (r.account ? accountHex(r.account) : `guest:${r.name}`);

function say(server: string, channel: ChannelInfo, w: Waiting): void {
  w.timer = null;
  if (w.names.size === 0) return;
  const named = [...w.names];
  w.names.clear();
  w.lastAt = Date.now();
  const { line, all } = readersLine(named.map(([, name]) => shortName(name) || "someone"));
  addChannelMessage(server, channel.name, {
    user_id: 0,
    username: "",
    content: line,
    timestamp: Date.now(),
    kind: "notice",
    ...(all.length > 0 ? { names: all } : {}),
  });
  // Marked when said, not when seen: someone who quits inside the minute has named nobody
  const key = historyKey(server);
  const stable = stableName(channel);
  updateUiPrefs((p) => {
    const here = p.readers_named[key] ?? (p.readers_named[key] = {});
    here[stable] = [...(here[stable] ?? []), ...named.map(([id]) => id)];
  });
}

/** This device just handed these a key here, or recent chat. */
export function noteReaders(server: string, channelId: number, readers: readonly NamedReader[]): void {
  const channel = get(channels.peek(server)).find((c) => c.channel_id === channelId);
  if (!channel || readers.length === 0) return;
  if (!goesByList(channel, get(textSeats.peek(server)).get(channelId)?.gated ?? false)) return;
  const told = new Set(get(uiPrefs).readers_named[historyKey(server)]?.[stableName(channel)] ?? []);
  const id = `${server}/${channelId}`;
  let w = waiting.get(id);
  if (!w) waiting.set(id, (w = { names: new Map(), timer: null, lastAt: 0 }));
  for (const r of readers) {
    const who = identityOf(r);
    if (!told.has(who)) w.names.set(who, r.name);
  }
  if (w.names.size === 0 || w.timer !== null) return;
  const held = w;
  const wait = Math.max(0, held.lastAt + MERGE_MS - Date.now());
  if (wait === 0) say(server, channel, held);
  else held.timer = setTimeout(() => say(server, channel, held), wait);
}

/** Whether this `TextJoined` row takes away a gate this device saw. Remembered by log and by
 *  name, since a relay that lies about one can change the other. */
export function gateNoted(server: string, channel: ChannelInfo, gated: boolean): boolean {
  const key = serverKey(server);
  const marks = [channel.name, ...(channel.log ? [channel.log] : [])];
  const seen = get(uiPrefs).gates_seen[key] ?? [];
  const had = marks.some((m) => seen.includes(m));
  if (gated === had) return false;
  updateUiPrefs((p) => {
    const list = (p.gates_seen[key] ?? []).filter((m) => !marks.includes(m));
    if (gated) list.push(...marks);
    if (list.length > 0) p.gates_seen[key] = list;
    else delete p.gates_seen[key];
  });
  return had && !gated;
}

/** Whether a relay now speaks an older protocol than it has to this device. It is the existing
 *  way to talk to an old relay, and also how a hostile one would strip all of the above. */
export function relayWentBack(server: string, protocol: number): boolean {
  const key = serverKey(server);
  if (!key) return false;
  const newest = get(uiPrefs).newest_protocol[key] ?? 0;
  if (protocol > newest) {
    updateUiPrefs((p) => {
      p.newest_protocol[key] = protocol;
    });
  }
  return protocol < newest;
}

/** A connection's naming goes with it; what was said is in the prefs. */
export function clearNoticing(server: string): void {
  for (const [id, w] of waiting) {
    if (!id.startsWith(`${server}/`)) continue;
    if (w.timer !== null) clearTimeout(w.timer);
    waiting.delete(id);
  }
}
