// The lists of the channels where who is there matters: a gate, or joined by hand.
//
// `sweep-rules.ts` says why they are asked for all at once. What is drawn and what a hand-off
// is checked against is the last sweep, plus whoever this app exchanged a key with since; a
// `MemberGone` takes someone off at once. Refresh is a person's own act, and tells the relay.

import { get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import { joinedTextChannelIds } from "./chat.js";
import { channels } from "./channels.js";
import { channelRosters, goneFrom, onlineById, setRoster, textSeats } from "./rosters.js";
import { accountHex } from "./account.js";
import { askProfiles } from "./profiles.js";
import { goesByList } from "../follow-rules.js";
import { firstSweepDelay, mayMoveUp, nextSweepDelay, pageBytes, pagePeople } from "../sweep-rules.js";
import type { UserInfo } from "../types.js";

/** What waited for a sweep gives up after this: its asker has stopped listening. */
const WAIT_MS = 30_000;
/** No answer for this long: the relay is not going to, and the next one starts afresh. */
const STUCK_MS = 30_000;
/** A relay can name a next page for ever: past this, far over any real channel, what came is
 *  the list. Asks waiting behind a run, the oldest going. */
const PAGES_MOST = 256;
const WAITING_MOST = 64;

interface Run {
  /** Channels to ask, the current one first. */
  queue: number[];
  /** Pages so far of the current one, and who was gone since it began. */
  people: UserInfo[];
  gone: Set<number>;
  /** Of the current one: how many pages, and how far the last said it went. */
  pages: number;
  after: number;
  bytes: number;
  /** Part of the schedule, not a person's Refresh. */
  scheduled: boolean;
  stuck: ReturnType<typeof setTimeout>;
}

interface Sweeps {
  /** The first `TextJoined` came: the schedule runs. */
  started: boolean;
  timer: ReturnType<typeof setTimeout> | null;
  lastAt: number;
  lastBytes: number;
  run: Run | null;
  /** Quiet channels are not swept: opening one tells the relay anyway. */
  quiet: ReadonlySet<number>;
  /** Hand-offs that wait to see whether their asker is on the next list. */
  waiting: { at: number; retry: () => void }[];
}

const sweeps = new Map<string, Sweeps>();

function stateOf(server: string): Sweeps {
  let s = sweeps.get(server);
  if (!s) sweeps.set(server, (s = { started: false, timer: null, lastAt: 0, lastBytes: 0, run: null, quiet: new Set(), waiting: [] }));
  return s;
}

function toSweep(server: string, s: Sweeps): number[] {
  const seats = get(textSeats.peek(server));
  const joined = get(joinedTextChannelIds.peek(server));
  return get(channels.peek(server))
    .filter((c) => c.text && joined.has(c.channel_id) && !s.quiet.has(c.channel_id) && goesByList(c, seats.get(c.channel_id)?.gated ?? false))
    .map((c) => c.channel_id);
}

function ask(server: string, channelId: number, after: number): void {
  invoke("request_channel_page", { server, channelId, after }).catch(() => finishRun(server));
}

function arm(server: string, s: Sweeps, ms: number): void {
  if (s.timer !== null) clearTimeout(s.timer);
  s.timer = setTimeout(() => startRun(server, toSweep(server, s), true), ms);
}

function startRun(server: string, queue: number[], scheduled: boolean): void {
  const s = stateOf(server);
  if (scheduled && s.timer !== null) {
    clearTimeout(s.timer);
    s.timer = null;
  }
  if (s.run) {
    // Inside what is under way, next after the page it waits for
    s.run.queue.splice(1, 0, ...queue.filter((id) => !s.run!.queue.includes(id)));
    s.run.scheduled ||= scheduled;
    return;
  }
  s.run = { queue, people: [], gone: new Set(), pages: 0, after: 0, bytes: 0, scheduled, stuck: setTimeout(() => finishRun(server), STUCK_MS) };
  if (queue.length === 0) finishRun(server);
  else ask(server, queue[0], 0);
}

function finishRun(server: string): void {
  const s = sweeps.get(server);
  const run = s?.run;
  if (!s || !run) return;
  clearTimeout(run.stuck);
  s.run = null;
  if (run.scheduled) {
    s.lastAt = Date.now();
    s.lastBytes = run.bytes;
    arm(server, s, nextSweepDelay(run.bytes));
  }
  const waiting = s.waiting;
  s.waiting = [];
  for (const w of waiting) if (Date.now() - w.at < WAIT_MS) w.retry();
}

/** The first `TextJoined` of a connection: the sweeps start. */
export function startSweeps(server: string, random = Math.random()): void {
  const s = stateOf(server);
  if (s.started) return;
  s.started = true;
  arm(server, s, firstSweepDelay(random));
}

/** The list of one channel now, because a person asked to see it, or just entered it. */
export function refreshList(server: string, channelId: number): void {
  startRun(server, [channelId], false);
}

/**
 * A stranger asks for a channel's chat. They may have just arrived, so the whole next sweep
 * moves up if its budget lets it, and never that one page, which would name the channel. If
 * it does not, or they are not on it, they get no answer.
 */
export function sweepForAsker(server: string, retry: () => void): void {
  const s = stateOf(server);
  if (!s.run?.scheduled && !mayMoveUp(Date.now() - s.lastAt, s.lastBytes)) return;
  if (s.waiting.length >= WAITING_MOST) s.waiting.shift();
  s.waiting.push({ at: Date.now(), retry });
  if (!s.run?.scheduled) startRun(server, toSweep(server, s), true);
}

/** A page came. False when no sweep asked it: the rest of a list too long for one frame. */
export function onSweepPage(
  server: string,
  page: { channel_id: number; ids?: number[]; rows: UserInfo[]; next: number },
): boolean {
  const run = sweeps.get(server)?.run;
  if (!run || run.queue[0] !== page.channel_id) return false;
  clearTimeout(run.stuck);
  run.stuck = setTimeout(() => finishRun(server), STUCK_MS);
  const online = onlineById(server);
  const known = get(channelRosters.peek(server)).get(page.channel_id) ?? [];
  const ids = page.ids ?? [];
  run.bytes += pageBytes(ids.length, page.rows.length);
  run.people.push(...pagePeople(ids, page.rows, (id) => online.get(id) ?? known.find((u) => u.user_id === id)));
  run.pages++;
  if (page.next > run.after && run.pages < PAGES_MOST) {
    run.after = page.next;
    ask(server, page.channel_id, page.next);
    return true;
  }
  const once = new Map(run.people.filter((u) => !run.gone.has(u.user_id)).map((u) => [u.user_id, u]));
  setRoster(server, page.channel_id, [...once.values()]);
  // Their names now, with the whole sweep's: asked when the list is drawn, they say which one is
  askProfiles(server, [...once.values()].flatMap((u) => (u.account ? [accountHex(u.account)] : [])));
  // Whoever it names is there, and whoever `MemberGone` named is off it by now, apart from
  // those who went while it was on its way
  const gone = run.gone;
  goneFrom.of(server).update((had) => {
    const next = new Map(had);
    if (gone.size > 0) next.set(page.channel_id, gone);
    else next.delete(page.channel_id);
    return next;
  });
  run.queue.shift();
  run.people = [];
  run.gone = new Set();
  run.pages = 0;
  run.after = 0;
  if (run.queue.length > 0) ask(server, run.queue[0], 0);
  else finishRun(server);
  return true;
}

/** `MemberGone`: off the list now, and they get no answer from here. */
export function noteMemberGone(server: string, channelId: number, id: number): void {
  const run = sweeps.get(server)?.run;
  if (run?.queue[0] === channelId) run.gone.add(id);
  goneFrom.of(server).update((had) => {
    const next = new Map(had);
    next.set(channelId, new Set([...(had.get(channelId) ?? []), id]));
    return next;
  });
  channelRosters.of(server).update((m) => {
    const list = m.get(channelId);
    if (!list?.some((u) => u.user_id === id)) return m;
    return new Map(m).set(channelId, list.filter((u) => u.user_id !== id));
  });
}

/** Which channels stay out of the sweep. */
export function setSweepQuiet(server: string, quiet: ReadonlySet<number>): void {
  stateOf(server).quiet = quiet;
}

/** A connection's sweeps die with it. */
export function clearSweeps(server: string): void {
  const s = sweeps.get(server);
  if (!s) return;
  if (s.timer !== null) clearTimeout(s.timer);
  if (s.run) clearTimeout(s.run.stuck);
  sweeps.delete(server);
}
