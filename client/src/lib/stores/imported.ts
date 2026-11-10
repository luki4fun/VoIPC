// What came from Discord, as the pane on screen holds it (ArchivePane.svelte).
//
// **Not `chat.ts`, not `channelMessages`, not the device's chat archive, not storage.**
// The word collides: `populateFromArchive` and `chat.archive` are this device's own
// sealed history. These rows are the relay's to read and nobody signed them, so they
// live here, in memory, while the pane is open. A reload forgets them, and nothing of
// the archive stays on a device.
//
// Every write names its server (`.of`), in the one listener below or a press. A reply
// for another channel, thread or query is dropped: the reader has moved on.

import { get } from "svelte/store";
import { invoke } from "@tauri-apps/api/core";

import {
  afterMine,
  archiveDeletedLine,
  idAfter,
  isTakenBack,
  mergeArchiveRows,
  mineDoneLine,
  pageHasArchive,
  refusedForNow,
  SEARCH_HITS,
  takenBack,
} from "../archive-rules.js";
import { fromServer, listenServer } from "../connect.js";
import { lastOp } from "./admin-ops.js";
import { account } from "./account.js";
import { livePath } from "../relay-rules.js";
import { olderRelay } from "./relay.js";
import { addNotification } from "./notifications.js";
import { scoped } from "./scoped.js";
import type { AdminReply, ArchiveAction, ArchiveRow, ArchiveScope } from "../types.js";

export interface ImportedSearch {
  query: string;
  rows: ArchiveRow[];
  /** The `from` asked for and not answered yet; null: nothing is out. */
  asking: string | null;
  /** Carry on from here; "" at the channel's end. */
  next: string;
  scanned: number;
  /** Hits to gather before waiting to be asked for more. */
  wanted: number;
}

export interface ImportedView {
  channel: number;
  /** "" the channel's own flow. */
  thread: string;
  /** The row that opens it, when opened from one. */
  threadRow: ArchiveRow | null;
  pinned: boolean;
  /** "" from the newest; else the `before` this list starts at. */
  from: string;
  /** Newest first, each once. */
  rows: ArchiveRow[];
  /** The `before` asked for and not answered yet; null: nothing is out. */
  asking: string | null;
  /** The answer replaces the rows, rather than going under them. */
  replacing: boolean;
  /** The `before` of the next page; "" nothing older. */
  next: string;
  /** The row to show, once it has come. */
  focus: string;
  search: ImportedSearch | null;
  error: string;
  /** Where the back button goes. */
  back: ImportedView | null;
}

/** The channels of this connection known to have an archive. */
export const importedHas = scoped<Set<number>>(() => new Set());
/** The pane's list; null while it is shut. */
export const importedView = scoped<ImportedView | null>(() => null);
/** Settings: how many of this account's rows there are, or why it cannot be told. */
export const importedMine = scoped<{ rows: number | null; refused: string }>(() => ({ rows: null, refused: "" }));

/** Channels asked about on this connection. It goes with the connection (`dropServer`),
 *  as `autoJoinAsked` does, so a reconnect asks again: ids of channels restart with a relay. */
const asked = scoped<Set<number>>(() => new Set());
/** Those still waiting for their answer: a refusal says no channel, so it covers them all. */
const probing = scoped<Set<number>>(() => new Set());
/** Bumped when what was asked may have changed, so the chat on screen asks again. */
export const importedRound = scoped<number>(() => 0);

interface MineAsk {
  action: ArchiveAction;
  id: string | null;
}
/** Own steps out, oldest first: a connection's requests are answered in order, and a reply
 *  does not say which row it was. */
const mineAsked = scoped<MineAsk[]>(() => []);

const VIEW_DEPTH = 4;

function fresh(channel: number, over: Partial<ImportedView> = {}): ImportedView {
  return {
    channel,
    thread: "",
    threadRow: null,
    pinned: false,
    from: "",
    rows: [],
    asking: null,
    replacing: false,
    next: "",
    focus: "",
    search: null,
    error: "",
    back: null,
    ...over,
  };
}

function depth(v: ImportedView | null): number {
  return v ? 1 + depth(v.back) : 0;
}

/** This view, without the oldest it would come back to. */
function withoutOldest(v: ImportedView): ImportedView | null {
  return v.back ? { ...v, back: withoutOldest(v.back) } : null;
}

/** Somewhere to come back to, without a chain of old lists held for ever: the oldest goes. */
function pushed(v: ImportedView): ImportedView | null {
  return depth(v) >= VIEW_DEPTH ? withoutOldest(v) : v;
}

function request(server: string, body: object | string, failed: (e: string) => void = () => {}): void {
  invoke("account_request", { server, request: body }).catch((e: unknown) => failed(String(e)));
}

function say(server: string, patch: Partial<ImportedView>): void {
  importedView.of(server).update((v) => (v ? { ...v, ...patch } : v));
}

function fetchPage(server: string, v: ImportedView, before: string): void {
  request(
    server,
    { ArchiveFetch: { channel_id: v.channel, thread: v.thread, before, pinned: v.pinned } },
    (error) => say(server, { error, asking: null }),
  );
}

/** Whether this channel has an archive, once per channel per connection. From an effect,
 *  never a template: it writes. */
export function probeImported(server: string, channel: number): void {
  const seen = get(asked.of(server));
  if (seen.has(channel)) return;
  seen.add(channel);
  get(probing.of(server)).add(channel);
  request(server, { ArchiveFetch: { channel_id: channel, thread: "", before: "", pinned: false } }, () => {
    seen.delete(channel);
    get(probing.of(server)).delete(channel);
  });
}

const listAsks = new Map<string, ReturnType<typeof setTimeout>>();

/**
 * Which channels this connection stands in hold an archive, all at once (protocol 21): so
 * opening one tells the relay nothing, as a first page on opening did. It answers for what
 * this session is in now, so a join asks again, a few together as one.
 */
export function askArchiveChannels(server: string): void {
  if (listAsks.has(server) || !get(account.peek(server))) return;
  listAsks.set(
    server,
    setTimeout(() => {
      listAsks.delete(server);
      request(server, "ArchiveChannels");
    }, 250),
  );
}

/** An import ended or was undone: what was learned of channels no longer holds. */
export function importedChanged(server: string): void {
  asked.of(server).set(new Set());
  probing.of(server).set(new Set());
  importedHas.of(server).set(new Set());
  importedRound.of(server).update((n) => n + 1);
  if (livePath(get(olderRelay.peek(server))?.protocol ?? null)) askArchiveChannels(server);
}

export function openImported(server: string, channel: number): void {
  const v = fresh(channel, { asking: "" });
  importedView.of(server).set(v);
  fetchPage(server, v, "");
}

export function closeImported(server: string): void {
  importedView.of(server).set(null);
}

/** The next page of the list, if there is one and none is out. */
export function importedOlder(server: string): void {
  const v = get(importedView.peek(server));
  if (!v || v.asking !== null || v.next === "" || v.search) return;
  say(server, { asking: v.next });
  fetchPage(server, v, v.next);
}

function show(server: string, v: ImportedView): void {
  const asking = v.from;
  importedView.of(server).set({ ...v, asking });
  fetchPage(server, v, asking);
}

/** A thread, in the pane: its own rows, with a way back. */
export function importedThread(server: string, row: ArchiveRow): void {
  const v = get(importedView.peek(server));
  if (v) show(server, fresh(v.channel, { thread: row.id, threadRow: row, back: pushed(v) }));
}

export function importedPins(server: string): void {
  const v = get(importedView.peek(server));
  if (!v) return;
  if (v.pinned) importedBack(server);
  else show(server, fresh(v.channel, { pinned: true, back: pushed(v) }));
}

export function importedBack(server: string): void {
  const v = get(importedView.peek(server));
  if (!v?.back) return;
  const { back } = v;
  importedView.of(server).set(back);
  // Left with an answer out, which was dropped for being about another list: asked again
  if (back.asking !== null) fetchPage(server, back, back.asking);
  if (back.search && back.search.asking !== null) askHits(server, back, back.search.query, back.search.asking);
  if (back.threadRow && isTakenBack(back.threadRow)) askOpening(server, back);
}

/** The page ending at this row, wherever it stands: no paging forward from there, so
 *  "Back to the newest" is how to return. */
export function importedShowAt(server: string, row: { id: string; thread: string }): void {
  const v = get(importedView.peek(server));
  if (!v) return;
  const from = idAfter(row.id);
  if (from) show(server, fresh(v.channel, { thread: row.thread, from, focus: row.id, back: pushed(v) }));
}

/** At the cap: the list starts again from where it reached, which caps what is held. */
export function importedFurther(server: string): void {
  const v = get(importedView.peek(server));
  if (v && v.next !== "") show(server, fresh(v.channel, { thread: v.thread, threadRow: v.threadRow, pinned: v.pinned, from: v.next, back: v.back }));
}

export function importedNewest(server: string): void {
  const v = get(importedView.peek(server));
  if (v) show(server, fresh(v.channel, { thread: v.thread, threadRow: v.threadRow, pinned: v.pinned, back: v.back }));
}

/** The row that opens this thread, as the relay serves it now: filed in the flow, and first
 *  on the page ending at it. */
function askOpening(server: string, v: ImportedView): void {
  if (v.threadRow) request(server, { ArchiveFetch: { channel_id: v.channel, thread: "", before: idAfter(v.threadRow.id), pinned: false } });
}

/** A view on the way back, after someone's posts were removed: it asks again when it comes
 *  back (`importedBack`), and until then shows nothing of whose its opening row was. */
function askedAgain(v: ImportedView): ImportedView {
  return {
    ...v,
    threadRow: v.threadRow && takenBack(v.threadRow),
    asking: v.from,
    replacing: true,
    search: v.search && { ...v.search, rows: [], asking: "", next: "", scanned: 0 },
    back: v.back && askedAgain(v.back),
  };
}

/** The same list again, for what a page cannot be told of: someone's posts were removed. A
 *  reader may not know whose, so the opening row says nothing until the relay has said. */
function reload(server: string): void {
  const v = get(importedView.peek(server));
  if (!v) return;
  say(server, { threadRow: v.threadRow && takenBack(v.threadRow), back: v.back && askedAgain(v.back) });
  askOpening(server, v);
  if (v.search) importedSearch(server, v.search.query);
  else {
    say(server, { asking: v.from, replacing: true });
    fetchPage(server, v, v.from);
  }
}

// ── Search: the relay gets the words ───────────────────────────────────────

function askHits(server: string, v: ImportedView, query: string, from: string): void {
  request(server, { ArchiveSearch: { channel_id: v.channel, query, from } }, (error) => say(server, { error }));
}

function searching(server: string, query: string): ImportedSearch | null {
  const s = get(importedView.peek(server))?.search;
  return s && s.query === query ? s : null;
}

/** Another request a second later, if the reader is still on this search. */
function askAgain(server: string, query: string, from: string): void {
  setTimeout(() => {
    const v = get(importedView.peek(server));
    const s = searching(server, query);
    if (!v || !s || s.asking !== from) return;
    askHits(server, v, query, from);
  }, 1000);
}

export function importedSearch(server: string, query: string): void {
  const v = get(importedView.peek(server));
  const q = query.trim();
  if (!v) return;
  if (!q) {
    say(server, { search: null, error: "" });
    return;
  }
  say(server, { error: "", search: { query: q, rows: [], asking: "", next: "", scanned: 0, wanted: SEARCH_HITS } });
  askHits(server, v, q, "");
}

export function importedSearchMore(server: string): void {
  const v = get(importedView.peek(server));
  const s = v?.search;
  if (!v || !s || s.next === "" || s.asking !== null) return;
  say(server, { search: { ...s, asking: s.next, wanted: s.rows.length + SEARCH_HITS } });
  askHits(server, v, s.query, s.next);
}

// ── Someone's own rows ─────────────────────────────────────────────────────

export function importedMineAsk(server: string, action: ArchiveAction, scope: ArchiveScope): void {
  get(mineAsked.of(server)).push({ action, id: typeof scope === "object" && "Message" in scope ? scope.Message.id : null });
  request(server, { ArchiveMine: { action, scope } }, (e) => addNotification(e, "warning"));
}

/** How many of this account's rows there are, for Settings. */
export function importedCount(server: string): void {
  importedMineAsk(server, "Count", "Everything");
}

// ── What the relay answers ─────────────────────────────────────────────────

interface Page {
  channel_id: number;
  thread: string;
  before: string;
  pinned: boolean;
  rows: ArchiveRow[];
  next: string;
}
interface Hits {
  channel_id: number;
  query: string;
  from: string;
  rows: ArchiveRow[];
  next: string;
  scanned: number;
}

function onPage(server: string, p: Page): void {
  if (p.thread === "" && p.before === "" && !p.pinned) {
    get(probing.of(server)).delete(p.channel_id);
    const on = pageHasArchive(p);
    if (get(importedHas.of(server)).has(p.channel_id) !== on) {
      importedHas.of(server).update((had) => {
        const next = new Set(had);
        if (on) next.add(p.channel_id);
        else next.delete(p.channel_id);
        return next;
      });
    }
  }
  const v = get(importedView.peek(server));
  const opener = v?.threadRow;
  if (opener && v.channel === p.channel_id && p.thread === "" && !p.pinned && p.before === idAfter(opener.id)) {
    const row = mergeArchiveRows([], p.rows).find((r) => r.id === opener.id);
    if (row) say(server, { threadRow: row });
    return;
  }
  if (!v || v.channel !== p.channel_id || v.thread !== p.thread || v.pinned !== p.pinned || v.asking !== p.before) return;
  importedView.of(server).set({
    ...v,
    rows: mergeArchiveRows(v.replacing ? [] : v.rows, p.rows),
    next: p.next,
    asking: null,
    replacing: false,
    error: "",
  });
}

function onHits(server: string, h: Hits): void {
  const v = get(importedView.peek(server));
  const s = searching(server, h.query);
  if (!v || !s || v.channel !== h.channel_id || s.asking !== h.from) return;
  // Newest first, whichever thread a hit is in
  const rows = mergeArchiveRows(s.rows, h.rows);
  const goOn = h.next !== "" && rows.length < s.wanted;
  say(server, { search: { ...s, rows, next: h.next, scanned: s.scanned + h.scanned, asking: goOn ? h.next : null } });
  if (goOn) askAgain(server, s.query, h.next);
}

function onMineDone(server: string, done: { action: ArchiveAction; rows: number }): void {
  const ask = get(mineAsked.of(server)).shift();
  if (done.action === "Count") {
    importedMine.of(server).set({ rows: done.rows, refused: "" });
    return;
  }
  if (ask?.id) {
    const { id } = ask;
    const action = done.action;
    importedView.of(server).update((v) => rowsAfter(v, action, id));
  } else {
    addNotification(`${fromServer(server)}${mineDoneLine(done.action, done.rows)}`, "info");
    reload(server);
    importedCount(server);
  }
}

/** One row's change, on the list, its search, and the way back, which holds the same
 *  rows and should not bring back one that went. */
function rowsAfter(v: ImportedView | null, action: "Hide" | "Show" | "Delete", id: string): ImportedView | null {
  if (!v) return v;
  return {
    ...v,
    rows: afterMine(v.rows, action, id),
    threadRow: v.threadRow && (afterMine([v.threadRow], action, id)[0] ?? null),
    search: v.search ? { ...v.search, rows: afterMine(v.search.rows, action, id) } : null,
    back: rowsAfter(v.back, action, id),
  };
}

function onAdminDeleted(server: string): void {
  const op = lastOp.get(server);
  const target = typeof op === "object" && op && "ArchiveDelete" in op ? op.ArchiveDelete.target : null;
  if (target && "Message" in target) {
    const { id } = target.Message;
    importedView.of(server).update((v) => rowsAfter(v, "Delete", id));
  } else {
    reload(server);
  }
}

/** A refusal of one of these is said where it was asked (`onRefused`), or not at all: the app
 *  asks some of them on its own, and a toast would be about nothing the person did. */
export function saysItsOwnRefusal(request: string): boolean {
  return request.startsWith("Archive");
}

function onRefused(server: string, request: string, reason: string): void {
  if (request === "ArchiveFetch") {
    // Asked again next time this channel comes on screen
    const open = get(probing.of(server));
    const seen = get(asked.of(server));
    for (const id of open) seen.delete(id);
    open.clear();
    const v = get(importedView.peek(server));
    if (!v || v.asking === null) return;
    if (refusedForNow(reason)) {
      const before = v.asking;
      setTimeout(() => {
        const now = get(importedView.peek(server));
        if (now && now.asking === before && now.channel === v.channel && now.thread === v.thread && now.pinned === v.pinned) fetchPage(server, now, before);
      }, 1000);
      return;
    }
    say(server, { error: reason, asking: null, replacing: false });
  } else if (request === "ArchiveSearch") {
    const s = get(importedView.peek(server))?.search;
    if (!s || s.asking === null) return;
    if (refusedForNow(reason)) askAgain(server, s.query, s.asking);
    else say(server, { error: reason, search: { ...s, asking: null } });
  } else if (request === "ArchiveMine") {
    const ask = get(mineAsked.of(server)).shift();
    if (ask?.id) addNotification(`${fromServer(server)}${reason}`, "warning");
    else importedMine.of(server).set({ rows: null, refused: reason });
  }
}

export function onImportedReply(server: string, raw: unknown): void {
  const r = raw as {
    ArchivePage?: Page;
    ArchiveHits?: Hits;
    ArchiveMineDone?: { action: ArchiveAction; rows: number };
    ArchiveChannels?: { channels: number[] };
    Admin?: AdminReply;
    Error?: { request: string; reason: string };
  };
  if (r.ArchivePage) onPage(server, r.ArchivePage);
  else if (r.ArchiveHits) onHits(server, r.ArchiveHits);
  else if (r.ArchiveMineDone) onMineDone(server, r.ArchiveMineDone);
  else if (r.ArchiveChannels) importedHas.of(server).set(new Set(r.ArchiveChannels.channels));
  else if (r.Error) onRefused(server, r.Error.request, r.Error.reason);
  else if (typeof r.Admin === "object" && r.Admin && "ArchiveDeleted" in r.Admin) {
    addNotification(`${fromServer(server)}${archiveDeletedLine(r.Admin.ArchiveDeleted.rows)}`, "info");
    onAdminDeleted(server);
  }
}

listenServer<unknown>("account-reply", onImportedReply);
// A ban's removal reaches readers by the wish at once: the marks say nothing of these rows
listenServer<unknown>("posts-hidden", (server) => reload(server));
