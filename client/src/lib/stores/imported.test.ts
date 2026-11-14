// What came from Discord, as the pane holds it: in memory, in its own list, and only what
// was asked for. A reply for another channel, thread or query goes nowhere.

import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { get } from "svelte/store";

const { invoked } = await import("./node-stores.mjs");
const {
  saysItsOwnRefusal,
  closeImported,
  importedBack,
  importedChanged,
  importedCount,
  importedFurther,
  importedHas,
  importedMine,
  importedMineAsk,
  importedOlder,
  importedPins,
  importedRound,
  importedSearch,
  importedSearchMore,
  importedShowAt,
  importedThread,
  importedView,
  onImportedReply,
  openImported,
  probeImported,
} = await import("./imported.ts");
const { channelMessages, dmMessages } = await import("./chat.ts");
const { dropServer } = await import("./scoped.ts");
const { lastOp } = await import("./admin-ops.ts");
const { notifications } = await import("./notifications.ts");

const S = "h.example:9987";
const OTHER = "o.example:9987";
const CHANNEL = 7;

const row = (id: string, over: object = {}) => ({
  id,
  author: "dan",
  author_id: "",
  at_ms: 1_700_000_000_000,
  body: `says ${id}`,
  thread: "",
  reply_to: "",
  reactions: [],
  pinned: false,
  thread_name: "",
  replies: 0,
  mine: false,
  hidden: false,
  ...over,
});

const page = (over: object = {}) => ({
  ArchivePage: { channel_id: CHANNEL, thread: "", before: "", pinned: false, rows: [row("9"), row("8")], next: "8", ...over },
});

const asks = () => invoked().filter(([c]: [string]) => c === "account_request").map(([, a]: [string, { request: object }]) => a.request);
const view = (server = S) => get(importedView.peek(server));

function fresh() {
  dropServer(S);
  dropServer(OTHER);
  invoked().length = 0;
}

test("once per channel per connection, and a reconnect asks again", () => {
  fresh();
  probeImported(S, CHANNEL);
  probeImported(S, CHANNEL);
  assert.deepEqual(asks(), [{ ArchiveFetch: { channel_id: CHANNEL, thread: "", before: "", pinned: false } }]);
  probeImported(S, CHANNEL + 1);
  assert.equal(asks().length, 2);
  dropServer(S);
  probeImported(S, CHANNEL);
  assert.equal(asks().length, 3, "ids of channels restart with a relay");
});

test("an answer says whether a channel has an archive, and a connection's end clears it", () => {
  fresh();
  onImportedReply(S, page());
  assert.ok(get(importedHas.peek(S)).has(CHANNEL));
  assert.ok(!get(importedHas.peek(OTHER)).has(CHANNEL), "each server its own");
  onImportedReply(S, page({ rows: [], next: "" }));
  assert.ok(!get(importedHas.peek(S)).has(CHANNEL), "an empty first page: nothing here");
  onImportedReply(S, page({ rows: [], next: "55" }));
  assert.ok(get(importedHas.peek(S)).has(CHANNEL), "a page of rows nobody may see moves on: there is one");
  dropServer(S);
  assert.equal(get(importedHas.peek(S)).size, 0);
});

test("a later page or another thread says nothing of whether a channel has one", () => {
  fresh();
  onImportedReply(S, page({ before: "5", rows: [row("4")], next: "" }));
  onImportedReply(S, page({ thread: "77", rows: [row("4")], next: "" }));
  onImportedReply(S, page({ pinned: true, rows: [row("4")], next: "" }));
  assert.equal(get(importedHas.peek(S)).size, 0);
});

test("the pane holds only what it asked for", () => {
  fresh();
  openImported(S, CHANNEL);
  assert.equal(view()?.asking, "");
  // Another channel, and one for the same channel's thread
  onImportedReply(S, page({ channel_id: CHANNEL + 1 }));
  onImportedReply(S, page({ thread: "77" }));
  onImportedReply(S, page({ pinned: true }));
  onImportedReply(S, page({ before: "100" }));
  assert.deepEqual(view()?.rows, [], "none of those");
  assert.equal(view()?.asking, "", "and it still waits");
  onImportedReply(S, page());
  assert.deepEqual(view()?.rows.map((r) => r.id), ["9", "8"]);
  assert.equal(view()?.asking, null);
  // The answer again, after the list moved on
  onImportedReply(S, page({ rows: [row("1")] }));
  assert.deepEqual(view()?.rows.map((r) => r.id), ["9", "8"], "a stale reply is dropped");
});

test("another server's page never lands in this pane", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(OTHER, page());
  assert.deepEqual(view()?.rows, []);
  assert.equal(view(OTHER), null);
});

test("older pages go under, one at a time, and the end is the end", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page());
  invoked().length = 0;
  importedOlder(S);
  importedOlder(S);
  assert.deepEqual(asks(), [{ ArchiveFetch: { channel_id: CHANNEL, thread: "", before: "8", pinned: false } }], "one out at a time");
  onImportedReply(S, page({ before: "8", rows: [row("7"), row("8")], next: "" }));
  assert.deepEqual(view()?.rows.map((r) => r.id), ["9", "8", "7"], "each once");
  invoked().length = 0;
  importedOlder(S);
  assert.deepEqual(asks(), [], "nothing older is left");
});

test("closing lets everything go, and a late answer does not bring it back", () => {
  fresh();
  openImported(S, CHANNEL);
  closeImported(S);
  assert.equal(view(), null);
  onImportedReply(S, page());
  assert.equal(view(), null);
});

test("a thread is a list of its own, and the back button is where it was", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page({ rows: [row("9", { thread_name: "Plans", replies: 2 })], next: "" }));
  importedThread(S, view()!.rows[0]);
  assert.equal(view()?.thread, "9");
  assert.deepEqual(view()?.rows, []);
  onImportedReply(S, page({ thread: "9", rows: [row("12"), row("11")], next: "" }));
  assert.deepEqual(view()?.rows.map((r) => r.id), ["12", "11"]);
  importedBack(S);
  assert.equal(view()?.thread, "");
  assert.deepEqual(view()?.rows.map((r) => r.id), ["9"]);
});

test("a way back stays four deep, the oldest going, and every view keeps one", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page({ rows: [row("9", { thread_name: "A", replies: 1 })], next: "" }));
  const opener = view()!.rows[0];
  for (const n of [1, 2, 3, 4, 5, 6]) {
    importedThread(S, { ...opener, id: String(100 + n) });
    assert.ok(view()?.back, `at step ${n}`);
  }
  const held = (v = view(), n = 0): number => (v ? held(v.back, n + 1) : n);
  assert.equal(held(), 4);
  // The pin button goes through the same way, and at this depth it did nothing
  importedPins(S);
  assert.equal(view()?.pinned, true);
  assert.equal(held(), 4);
  importedPins(S);
  assert.equal(view()?.pinned, false, "and the way out of it works");
  assert.equal(view()?.thread, "106");
  while (view()?.back) importedBack(S);
  assert.equal(view()?.thread, "104", "the oldest of those left, each older one gone in turn");
});

test("a view left with a page out asks again on the way back", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page());
  importedOlder(S);
  assert.equal(view()?.asking, "8");
  importedPins(S);
  // The reply lands while on the other view, which drops it
  onImportedReply(S, page({ before: "8", rows: [row("7")], next: "" }));
  assert.deepEqual(view()?.rows, []);
  invoked().length = 0;
  importedBack(S);
  assert.deepEqual(asks(), [{ ArchiveFetch: { channel_id: CHANNEL, thread: "", before: "8", pinned: false } }]);
  onImportedReply(S, page({ before: "8", rows: [row("7")], next: "" }));
  assert.deepEqual(view()?.rows.map((r) => r.id), ["9", "8", "7"], "under what it had");
  assert.equal(view()?.asking, null, "and it can page again");
  // A view with nothing out asks nothing
  importedPins(S);
  invoked().length = 0;
  importedBack(S);
  assert.deepEqual(asks(), []);
});

test("so does a search", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page());
  importedSearch(S, "word");
  importedThread(S, row("9", { thread_name: "A", replies: 1 }));
  invoked().length = 0;
  importedBack(S);
  assert.deepEqual(asks(), [{ ArchiveSearch: { channel_id: CHANNEL, query: "word", from: "" } }]);
});

test("pins are a toggle over the list", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page());
  invoked().length = 0;
  importedPins(S);
  assert.equal(view()?.pinned, true);
  assert.deepEqual(asks(), [{ ArchiveFetch: { channel_id: CHANNEL, thread: "", before: "", pinned: true } }]);
  importedPins(S);
  assert.equal(view()?.pinned, false);
  assert.deepEqual(view()?.rows.map((r) => r.id), ["9", "8"]);
});

test("Show here asks for the page ending at that row, as a decimal string", () => {
  fresh();
  openImported(S, CHANNEL);
  invoked().length = 0;
  importedShowAt(S, { id: "1454987148113234751", thread: "1454987148113230000" });
  assert.deepEqual(asks(), [
    { ArchiveFetch: { channel_id: CHANNEL, thread: "1454987148113230000", before: "1454987148113234752", pinned: false } },
  ]);
  assert.equal(view()?.focus, "1454987148113234751");
  assert.ok(view()?.back, "a way back to where it was asked from");
});

test("Go further back starts the list again from where it reached", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page());
  invoked().length = 0;
  importedFurther(S);
  assert.deepEqual(view()?.rows, [], "which is what caps what is held");
  assert.equal(view()?.from, "8");
  assert.deepEqual(asks(), [{ ArchiveFetch: { channel_id: CHANNEL, thread: "", before: "8", pinned: false } }]);
});

test("a search keeps to its own question", () => {
  fresh();
  openImported(S, CHANNEL);
  importedSearch(S, "first");
  importedSearch(S, " second ");
  onImportedReply(S, { ArchiveHits: { channel_id: CHANNEL, query: "first", from: "", rows: [row("1")], next: "", scanned: 10 } });
  assert.deepEqual(view()?.search?.rows, [], "the last question's answer only");
  onImportedReply(S, { ArchiveHits: { channel_id: CHANNEL, query: "second", from: "", rows: [row("2")], next: "", scanned: 10 } });
  assert.deepEqual(view()?.search?.rows.map((r) => r.id), ["2"]);
  assert.equal(view()?.search?.scanned, 10);
  assert.equal(view()?.search?.asking, null);
  importedSearch(S, "");
  assert.equal(view()?.search, null, "no words: back to the list");
});

test("an answer to an earlier step of the same search adds nothing", () => {
  fresh();
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    openImported(S, CHANNEL);
    importedSearch(S, "word");
    onImportedReply(S, { ArchiveHits: { channel_id: CHANNEL, query: "word", from: "", rows: [row("1")], next: "0:5", scanned: 100 } });
    assert.equal(view()?.search?.asking, "0:5");
    onImportedReply(S, { ArchiveHits: { channel_id: CHANNEL, query: "word", from: "", rows: [row("9")], next: "0:7", scanned: 100 } });
    assert.deepEqual(view()?.search?.rows.map((r) => r.id), ["1"]);
    assert.equal(view()?.search?.scanned, 100);
    assert.equal(view()?.search?.asking, "0:5", "it goes on waiting for the one it asked");
  } finally {
    mock.timers.reset();
  }
});

test("a search carries on a second later, while it is wanted, and stops when it is not", () => {
  fresh();
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    openImported(S, CHANNEL);
    importedSearch(S, "word");
    invoked().length = 0;
    onImportedReply(S, { ArchiveHits: { channel_id: CHANNEL, query: "word", from: "", rows: [row("1")], next: "0:5", scanned: 100 } });
    mock.timers.tick(999);
    assert.deepEqual(asks(), [], "not at once: at most one a second");
    mock.timers.tick(1);
    assert.deepEqual(asks(), [{ ArchiveSearch: { channel_id: CHANNEL, query: "word", from: "0:5" } }]);
    onImportedReply(S, { ArchiveHits: { channel_id: CHANNEL, query: "word", from: "0:5", rows: [row("2")], next: "0:3", scanned: 100 } });
    assert.equal(view()?.search?.scanned, 200, "looked at, added up");
    invoked().length = 0;
    // A new question, or closing, ends what was going
    closeImported(S);
    mock.timers.tick(1000);
    assert.deepEqual(asks(), []);
  } finally {
    mock.timers.reset();
  }
});

test("fifty hits wait to be asked for more", () => {
  fresh();
  openImported(S, CHANNEL);
  importedSearch(S, "word");
  invoked().length = 0;
  const hits = Array.from({ length: 50 }, (_, i) => row(String(100 + i)));
  onImportedReply(S, { ArchiveHits: { channel_id: CHANNEL, query: "word", from: "", rows: hits, next: "0:5", scanned: 100 } });
  assert.equal(view()?.search?.asking, null);
  importedSearchMore(S);
  assert.deepEqual(asks(), [{ ArchiveSearch: { channel_id: CHANNEL, query: "word", from: "0:5" } }]);
});

test("too many requests waits a second and goes on; anything else is said", () => {
  fresh();
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    openImported(S, CHANNEL);
    importedSearch(S, "word");
    invoked().length = 0;
    onImportedReply(S, { Error: { request: "ArchiveSearch", reason: "Too many requests at once; slow down." } });
    assert.equal(view()?.error, "");
    mock.timers.tick(1000);
    assert.deepEqual(asks(), [{ ArchiveSearch: { channel_id: CHANNEL, query: "word", from: "" } }]);
    onImportedReply(S, { Error: { request: "ArchiveSearch", reason: "Join the channel first." } });
    assert.equal(view()?.error, "Join the channel first.");
    assert.equal(view()?.search?.asking, null);

    importedSearch(S, "");
    invoked().length = 0;
    onImportedReply(S, page());
    importedOlder(S);
    invoked().length = 0;
    onImportedReply(S, { Error: { request: "ArchiveFetch", reason: "Too many requests at once; slow down." } });
    mock.timers.tick(1000);
    assert.deepEqual(asks(), [{ ArchiveFetch: { channel_id: CHANNEL, thread: "", before: "8", pinned: false } }], "the same page again");
  } finally {
    mock.timers.reset();
  }
});

test("a refused probe is asked again next time, and shows nothing", () => {
  fresh();
  probeImported(S, CHANNEL);
  onImportedReply(S, { Error: { request: "ArchiveFetch", reason: "Join the channel first." } });
  assert.equal(get(importedHas.peek(S)).size, 0);
  invoked().length = 0;
  probeImported(S, CHANNEL);
  assert.equal(asks().length, 1);
});

test("someone's own step changes that row, and the way back with it", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page({ rows: [row("9", { mine: true }), row("8", { mine: true })], next: "" }));
  importedMineAsk(S, "Hide", { Message: { channel_id: CHANNEL, id: "9" } });
  onImportedReply(S, { ArchiveMineDone: { action: "Hide", rows: 1 } });
  assert.deepEqual(view()?.rows.map((r) => r.hidden), [true, false]);
  importedMineAsk(S, "Show", { Message: { channel_id: CHANNEL, id: "9" } });
  onImportedReply(S, { ArchiveMineDone: { action: "Show", rows: 1 } });
  assert.deepEqual(view()?.rows.map((r) => r.hidden), [false, false]);
  importedPins(S);
  importedMineAsk(S, "Delete", { Message: { channel_id: CHANNEL, id: "9" } });
  onImportedReply(S, { ArchiveMineDone: { action: "Delete", rows: 1 } });
  importedPins(S);
  assert.deepEqual(view()?.rows.map((r) => r.id), ["8"], "gone from the list it would have come back to");
});

test("a step on a thread's opening row shows on it, on the way back too", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page({ rows: [row("9", { thread_name: "Plans", replies: 2, mine: true })], next: "" }));
  importedThread(S, view()!.rows[0]);
  onImportedReply(S, page({ thread: "9", rows: [row("12")], next: "" }));
  const own = (action: string, id = "9") => {
    importedMineAsk(S, action as never, { Message: { channel_id: CHANNEL, id } });
    onImportedReply(S, { ArchiveMineDone: { action, rows: 1 } });
  };
  own("Hide");
  assert.equal(view()?.threadRow?.hidden, true);
  own("Show");
  assert.equal(view()?.threadRow?.hidden, false);
  own("Hide", "12");
  assert.equal(view()?.threadRow?.hidden, false, "the control: another row's step leaves it");
  own("Delete");
  const gone = view()?.threadRow;
  assert.equal(gone?.body, "");
  assert.equal(gone?.author, "");
  assert.equal(gone?.mine, false, "with nothing left to press");
  assert.equal(gone?.thread_name, "Thread", "the name goes with it, and the header still has one");
  importedBack(S);
  assert.equal(view()?.rows[0].thread_name, "Thread", "the row in the list it came from too");
  assert.equal(view()?.rows[0].replies, 2);
});

test("an operator's Delete this on an opening row shows there too", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page({ rows: [row("9", { thread_name: "Plans", replies: 2 })], next: "" }));
  importedThread(S, view()!.rows[0]);
  lastOp.set(S, { ArchiveDelete: { target: { Message: { channel_id: CHANNEL, id: "9" } } } });
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 1 } } });
  assert.equal(view()?.threadRow?.body, "");
});

// A reader cannot tell whose posts went, so the row that opens a thread says nothing until the
// relay has said. Whose it was shows only on the row it serves.
const CAME_FROM = (id: string) => ({ ArchiveFetch: { channel_id: CHANNEL, thread: "", before: (BigInt(id) + 1n).toString(), pinned: false } });
const dans = { thread_name: "Plans", replies: 2, author_id: "123", mine: true };

function inThread(rowsAbove: object[] = []) {
  openImported(S, CHANNEL);
  onImportedReply(S, page({ rows: [row("9", dans), ...rowsAbove], next: "" }));
  importedThread(S, view()!.rows[0]);
  onImportedReply(S, page({ thread: "9", rows: [row("12")], next: "" }));
  invoked().length = 0;
}
const nothingOf = (r: { author: string; author_id: string; body: string; thread_name: string; mine: boolean } | null | undefined) => {
  assert.equal(r?.author, "");
  assert.equal(r?.author_id, "");
  assert.equal(r?.body, "");
  assert.equal(r?.thread_name, "Thread", "the title may be their words too");
  assert.equal(r?.mine, false, "and nothing left to press");
};

// W2-32
test("a removal under a search asks again for the list beneath it too", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page());
  importedSearch(S, "word");
  invoked().length = 0;
  lastOp.set(S, { ArchiveDelete: { target: { Author: { id: "123" } } } });
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 1 } } });
  assert.deepEqual(asks(), [
    { ArchiveSearch: { channel_id: CHANNEL, query: "word", from: "" } },
    { ArchiveFetch: { channel_id: CHANNEL, thread: "", before: "", pinned: false } },
  ]);
  onImportedReply(S, page({ rows: [row("8")] }));
  importedSearch(S, "");
  assert.deepEqual(view()?.rows.map((r) => r.id), ["8"], "Clear search shows what the relay serves now");
});

test("Delete everything by this author on an opening row leaves none of it drawn", () => {
  fresh();
  inThread();
  lastOp.set(S, { ArchiveDelete: { target: { Author: { id: "123" } } } });
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 40 } } });
  nothingOf(view()?.threadRow);
  assert.deepEqual(asks()[0], CAME_FROM("9"), "and the relay is asked what it serves");
  assert.deepEqual(asks()[1], { ArchiveFetch: { channel_id: CHANNEL, thread: "9", before: "", pinned: false } });
  // As it serves one: neutral, with the way in
  onImportedReply(S, page({ before: "10", rows: [row("9", { author: "", author_id: "", body: "", thread_name: "Thread", replies: 2 }), row("8")] }));
  nothingOf(view()?.threadRow);
  assert.equal(view()?.threadRow?.replies, 2);
  assert.deepEqual(view()?.rows.map((r) => r.id), ["12"], "that page is not the thread's list");
  assert.equal(view()?.asking, "", "which still waits for its own");
});

test("Delete all, and a removal reaching a reader, leave none of it drawn", () => {
  fresh();
  inThread();
  importedMineAsk(S, "Delete", "Everything");
  invoked().length = 0;
  onImportedReply(S, { ArchiveMineDone: { action: "Delete", rows: 3 } });
  nothingOf(view()?.threadRow);
  assert.deepEqual(asks()[0], CAME_FROM("9"));
});

test("a removal of someone else gives the row back, as the relay serves it", () => {
  fresh();
  inThread();
  lastOp.set(S, { ArchiveDelete: { target: { Author: { id: "555" } } } });
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 1 } } });
  nothingOf(view()?.threadRow);
  onImportedReply(S, page({ before: "10", rows: [row("9", dans), row("8")] }));
  assert.equal(view()?.threadRow?.body, "says 9", "the control: nobody took this one back");
  assert.equal(view()?.threadRow?.thread_name, "Plans");
  assert.equal(view()?.threadRow?.mine, true);
});

test("a time no Date can hold does not come in by the opening row", () => {
  fresh();
  inThread();
  lastOp.set(S, { ArchiveDelete: { target: { Author: { id: "555" } } } });
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 1 } } });
  onImportedReply(S, page({ before: "10", rows: [row("9", { ...dans, at_ms: 1e300 })] }));
  assert.equal(view()?.threadRow?.at_ms, 0);
});

test("no answer, or a page without it, leaves it saying nothing", () => {
  fresh();
  inThread();
  lastOp.set(S, { ArchiveDelete: { target: { Author: { id: "123" } } } });
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 1 } } });
  onImportedReply(S, page({ before: "10", rows: [], next: "8" }));
  nothingOf(view()?.threadRow);
  // Another channel's, or another page of the flow, is not about it
  onImportedReply(S, page({ channel_id: CHANNEL + 1, before: "10", rows: [row("9", dans)] }));
  onImportedReply(S, page({ before: "9", rows: [row("9", dans)] }));
  nothingOf(view()?.threadRow);
});

test("the way back holds none of it either: each view asks again when it comes back", () => {
  fresh();
  // A thread, and from it a jump to a row of the same thread
  inThread();
  importedShowAt(S, { id: "12", thread: "9" });
  onImportedReply(S, page({ thread: "9", before: "13", rows: [row("12")], next: "" }));
  invoked().length = 0;
  lastOp.set(S, { ArchiveDelete: { target: { Author: { id: "123" } } } });
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 1 } } });
  nothingOf(view()?.back?.threadRow);
  invoked().length = 0;
  importedBack(S);
  nothingOf(view()?.threadRow);
  assert.deepEqual(asks(), [{ ArchiveFetch: { channel_id: CHANNEL, thread: "9", before: "", pinned: false } }, CAME_FROM("9")]);
  onImportedReply(S, page({ thread: "9", rows: [row("15")], next: "" }));
  assert.deepEqual(view()?.rows.map((r) => r.id), ["15"], "the list asked for replaces what it held");
  // And the list under it, whose row is gone
  invoked().length = 0;
  importedBack(S);
  assert.deepEqual(asks(), [{ ArchiveFetch: { channel_id: CHANNEL, thread: "", before: "", pinned: false } }]);
  onImportedReply(S, page({ rows: [row("7")], next: "" }));
  assert.deepEqual(view()?.rows.map((r) => r.id), ["7"]);
});

test("a search on the way back starts again", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page({ rows: [row("9", dans)], next: "" }));
  importedSearch(S, "says");
  onImportedReply(S, { ArchiveHits: { channel_id: CHANNEL, query: "says", from: "", rows: [row("9", dans)], next: "", scanned: 9 } });
  importedThread(S, view()!.search!.rows[0]);
  lastOp.set(S, { ArchiveDelete: { target: { Author: { id: "123" } } } });
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 1 } } });
  assert.deepEqual(view()?.back?.search?.rows, []);
  invoked().length = 0;
  importedBack(S);
  assert.ok(asks().some((a: object) => JSON.stringify(a) === JSON.stringify({ ArchiveSearch: { channel_id: CHANNEL, query: "says", from: "" } })));
});

test("a step on one row asks nothing again, and a list with no thread open has no row to ask about", () => {
  fresh();
  inThread();
  lastOp.set(S, { ArchiveDelete: { target: { Message: { channel_id: CHANNEL, id: "12" } } } });
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 1 } } });
  assert.deepEqual(asks(), []);
  assert.equal(view()?.threadRow?.body, "says 9", "the control: its opening row stays");
  importedBack(S);
  invoked().length = 0;
  lastOp.set(S, { ArchiveDelete: { target: { Author: { id: "123" } } } });
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 1 } } });
  assert.equal(asks().length, 1, "only the list");
});

test("answers come in the order the steps went", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page({ rows: [row("9"), row("8")], next: "" }));
  importedMineAsk(S, "Hide", { Message: { channel_id: CHANNEL, id: "9" } });
  importedMineAsk(S, "Delete", { Message: { channel_id: CHANNEL, id: "8" } });
  onImportedReply(S, { ArchiveMineDone: { action: "Hide", rows: 1 } });
  assert.deepEqual(view()?.rows.map((r) => [r.id, r.hidden]), [["9", true], ["8", false]], "the first answer is about the first row");
  onImportedReply(S, { ArchiveMineDone: { action: "Delete", rows: 1 } });
  assert.deepEqual(view()?.rows.map((r) => r.id), ["9"]);
});

test("two steps out answer in order", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page({ rows: [row("9"), row("8")], next: "" }));
  importedMineAsk(S, "Delete", { Message: { channel_id: CHANNEL, id: "9" } });
  importedMineAsk(S, "Delete", { Message: { channel_id: CHANNEL, id: "8" } });
  onImportedReply(S, { Error: { request: "ArchiveMine", reason: "Hide or delete everything of yours here instead." } });
  assert.deepEqual(view()?.rows.map((r) => r.id), ["9", "8"], "the refused one stays");
  onImportedReply(S, { ArchiveMineDone: { action: "Delete", rows: 1 } });
  assert.deepEqual(view()?.rows.map((r) => r.id), ["9"], "and the second answer is about the second row");
});

test("Settings' count, and the refusal for no linked Discord", () => {
  fresh();
  importedCount(S);
  assert.deepEqual(asks(), [{ ArchiveMine: { action: "Count", scope: "Everything" } }]);
  onImportedReply(S, { ArchiveMineDone: { action: "Count", rows: 12 } });
  assert.deepEqual(get(importedMine.peek(S)), { rows: 12, refused: "" });
  importedCount(S);
  onImportedReply(S, { Error: { request: "ArchiveMine", reason: "Link your Discord account first: that is how this server knows which posts are yours." } });
  assert.equal(get(importedMine.peek(S)).rows, null);
  assert.match(get(importedMine.peek(S)).refused, /^Link your Discord/);
});

test("an archive ask's refusal gets no toast of its own, and anything else still does", () => {
  assert.equal(saysItsOwnRefusal("ArchiveMine"), true, "Settings' count, asked with no click");
  assert.equal(saysItsOwnRefusal("ArchiveFetch"), true);
  assert.equal(saysItsOwnRefusal("ArchiveChannels"), true);
  assert.equal(saysItsOwnRefusal("PasswordChange"), false);
});

test("Hide all counts again afterwards", () => {
  fresh();
  importedMineAsk(S, "Hide", "Everything");
  invoked().length = 0;
  onImportedReply(S, { ArchiveMineDone: { action: "Hide", rows: 12 } });
  assert.deepEqual(asks(), [{ ArchiveMine: { action: "Count", scope: "Everything" } }]);
});

test("Hide all and Show all say they worked, and a count and a single row say nothing", () => {
  fresh();
  notifications.set([]);
  const said = () => get(notifications).map((n: { message: string }) => n.message.replace(/^h\.example: /, ""));
  importedMineAsk(S, "Hide", "Everything");
  onImportedReply(S, { ArchiveMineDone: { action: "Hide", rows: 12 } });
  assert.deepEqual(said(), ["12 of your posts hidden."]);
  onImportedReply(S, { ArchiveMineDone: { action: "Count", rows: 12 } });
  importedMineAsk(S, "Show", "Everything");
  onImportedReply(S, { ArchiveMineDone: { action: "Show", rows: 12 } });
  assert.deepEqual(said(), ["12 of your posts hidden.", "12 of your posts shown again."]);
  onImportedReply(S, { ArchiveMineDone: { action: "Count", rows: 12 } });
  notifications.set([]);
  importedMineAsk(S, "Hide", { Message: { channel_id: CHANNEL, id: "9" } });
  onImportedReply(S, { ArchiveMineDone: { action: "Hide", rows: 1 } });
  assert.deepEqual(said(), []);
});

test("an operator's delete takes that row, or fetches again for someone's all", () => {
  fresh();
  openImported(S, CHANNEL);
  onImportedReply(S, page({ rows: [row("9"), row("8")], next: "" }));
  lastOp.set(S, { ArchiveDelete: { target: { Message: { channel_id: CHANNEL, id: "9" } } } });
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 1 } } });
  assert.deepEqual(view()?.rows.map((r) => r.id), ["8"]);
  lastOp.set(S, { ArchiveDelete: { target: { Author: { id: "123" } } } });
  invoked().length = 0;
  onImportedReply(S, { Admin: { ArchiveDeleted: { rows: 40 } } });
  assert.deepEqual(asks(), [{ ArchiveFetch: { channel_id: CHANNEL, thread: "", before: "", pinned: false } }]);
  onImportedReply(S, page({ rows: [row("3")], next: "" }));
  assert.deepEqual(view()?.rows.map((r) => r.id), ["3"], "that answer replaces the list");
});

test("after an import or an undo every channel is asked about anew", () => {
  fresh();
  probeImported(S, CHANNEL);
  onImportedReply(S, page());
  const round = get(importedRound.peek(S));
  importedChanged(S);
  assert.equal(get(importedHas.peek(S)).size, 0);
  assert.equal(get(importedRound.peek(S)), round + 1, "so the chat on screen asks");
  invoked().length = 0;
  probeImported(S, CHANNEL);
  assert.equal(asks().length, 1);
});

test("nothing of it reaches the chat, or storage", () => {
  fresh();
  const stored: unknown[] = [];
  const before = [get(channelMessages), get(dmMessages)];
  (globalThis as unknown as { localStorage: unknown }).localStorage = {
    setItem: (...a: unknown[]) => stored.push(a),
    getItem: () => null,
    removeItem: () => {},
  };
  openImported(S, CHANNEL);
  onImportedReply(S, page());
  importedSearch(S, "word");
  onImportedReply(S, { ArchiveHits: { channel_id: CHANNEL, query: "word", from: "", rows: [row("1")], next: "", scanned: 1 } });
  assert.equal(get(channelMessages), before[0], "the map itself: no write at all");
  assert.equal(get(dmMessages), before[1]);
  assert.deepEqual(stored, []);
  // Whichever command the store sends, it writes nothing down on this device
  assert.deepEqual([...new Set(invoked().map(([c]: [string]) => c))], ["account_request"]);
  // The file itself: no storage, and neither of the chat's own stores
  const source = readFileSync(join(import.meta.dirname, "imported.ts"), "utf8").replace(/^\s*(\/\/|\*|\/\*).*$/gm, "");
  assert.doesNotMatch(source, /localStorage|indexedDB|channelMessages|populateFromArchive|chat\.archive|uiPrefs|updateUiPrefs|from "\.\/chat/);
});

test("the live path's list says at connect which channels hold an archive, and opening asks nothing", () => {
  fresh();
  invoked().length = 0;
  onImportedReply(S, { ArchiveChannels: { channels: [CHANNEL, CHANNEL + 1] } });
  assert.deepEqual([...get(importedHas.peek(S))], [CHANNEL, CHANNEL + 1]);
  onImportedReply(S, { ArchiveChannels: { channels: [] } });
  assert.equal(get(importedHas.peek(S)).size, 0, "what it answers now is all of it");
  assert.equal(asks().length, 0);
  onImportedReply(S, { Error: { request: "ArchiveChannels", reason: "no" } });
  assert.equal(asks().length, 0, "a refusal asks nothing again");
});
