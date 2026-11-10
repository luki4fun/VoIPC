import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ARCHIVE_LABEL,
  ARCHIVE_SEARCH_HINT,
  THREAD_TAKEN_BACK,
  afterMine,
  archiveChips,
  archiveDeletedLine,
  compareIds,
  firstWords,
  idAfter,
  isTakenBack,
  lookedAt,
  mergeArchiveRows,
  mineDoneLine,
  mineLine,
  pageHasArchive,
  refusedForNow,
  replyLine,
  threadOpener,
} from "./archive-rules.ts";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse, plainText } from "./markdown.ts";
import { tokenize } from "./emote-rules.ts";
import type { ArchiveRow } from "./types.ts";

const row = (id: string, over: Partial<ArchiveRow> = {}): ArchiveRow => ({
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

test("the label says what it is, and the search says who sees it", () => {
  assert.equal(ARCHIVE_LABEL, "Imported from Discord, unverified. This server can read it.");
  assert.match(ARCHIVE_SEARCH_HINT, /The server sees what you search/);
});

test("two real snowflakes stay two, and in order", () => {
  const [a, b] = ["1454987148113234751", "1454987148113234752"];
  // The control: as numbers they are one
  assert.equal(Number(a), Number(b));
  assert.deepEqual(mergeArchiveRows([row(a)], [row(b)]).map((r) => r.id), [b, a]);
  assert.ok(compareIds(a, b) < 0);
});

test("a shorter id is older, whatever its digits say as text", () => {
  assert.deepEqual(mergeArchiveRows([], [row("99"), row("100")]).map((r) => r.id), ["100", "99"]);
  // The control: text alone would put 99 first the other way round
  assert.ok("99" > "100");
});

test("a repeated page leaves each row once, so a keyed each cannot throw", () => {
  const page = [row("5"), row("4")];
  assert.deepEqual(mergeArchiveRows(page, page).map((r) => r.id), ["5", "4"]);
  assert.equal(mergeArchiveRows([row("5", { body: "old" })], [row("5", { body: "new" })])[0].body, "new");
  assert.deepEqual(mergeArchiveRows([], []), []);
});

test("the page ending at a row holds that row", () => {
  assert.equal(idAfter("1454987148113234751"), "1454987148113234752");
  assert.equal(idAfter("9999999999999999999"), "10000000000000000000");
  // The control: through a number it lands on the same id, and the page misses the row
  assert.notEqual(String(Number("1454987148113234751") + 1), "1454987148113234752");
  assert.equal(idAfter(""), "");
  assert.equal(idAfter("12a"), "");
});

test("reactions are chips, each emoji once", () => {
  assert.deepEqual(
    archiveChips(row("1", { reactions: [{ emoji: "👍", count: 2 }, { emoji: ":pog:", count: 1 }, { emoji: "👍", count: 3 }] })),
    [{ emoji: "👍", count: 5 }, { emoji: ":pog:", count: 1 }],
  );
});

test("what a row answers shows when loaded, and says so when not", () => {
  const to = row("1", { author: "eva", body: "the\nfirst   words" });
  assert.equal(replyLine({ reply_to: "1" }, [to]), "replying to eva: the first words");
  assert.equal(replyLine({ reply_to: "2" }, [to]), "replying to an earlier message");
  // A root with no message of its own has nothing to quote
  assert.equal(replyLine({ reply_to: "3" }, [row("3", { author: "", body: "" })]), "replying to an earlier message");
  assert.equal(firstWords("x".repeat(100), 5), "xxxxx…");
  assert.equal(firstWords("😀".repeat(10), 2), "😀😀…", "never half a character");
});

test("a thread's opener counts", () => {
  assert.equal(threadOpener({ replies: 1, thread_name: "Plans" }), "1 reply, Plans");
  assert.equal(threadOpener({ replies: 1204, thread_name: "Plans" }), "1,204 replies, Plans");
  assert.equal(lookedAt(120_000), "Looked at 120,000 messages");
  assert.equal(lookedAt(1), "Looked at 1 message");
});

test("too many requests and a busy relay mean in a moment, and nothing else does", () => {
  assert.ok(refusedForNow("Too many requests at once; slow down."));
  assert.ok(refusedForNow("The server is busy searching. Try again in a moment."));
  assert.ok(!refusedForNow("Join the channel first."));
  assert.ok(!refusedForNow("Link your Discord account first: that is how this server knows which posts are yours."));
});

test("a page of rows nobody may see still says a channel has an archive", () => {
  assert.ok(pageHasArchive({ rows: [row("1")], next: "" }));
  assert.ok(pageHasArchive({ rows: [], next: "55" }));
  assert.ok(!pageHasArchive({ rows: [], next: "" }));
});

test("someone's own step changes that row and no other", () => {
  const rows = [row("2"), row("1")];
  assert.deepEqual(afterMine(rows, "Delete", "2").map((r) => r.id), ["1"]);
  assert.deepEqual(afterMine(rows, "Hide", "2").map((r) => r.hidden), [true, false]);
  assert.deepEqual(afterMine(afterMine(rows, "Hide", "2"), "Show", "2").map((r) => r.hidden), [false, false]);
});

test("a row that opens a thread stays when deleted, as the relay then serves it", () => {
  const rows = [row("2", { thread_name: "My diagnosis", replies: 40, mine: true, author_id: "7", reply_to: "1", pinned: true, reactions: [{ emoji: "x", count: 1 }] }), row("1")];
  const [root] = afterMine(rows, "Delete", "2");
  assert.deepEqual(root, row("2", { author: "", body: "", thread_name: THREAD_TAKEN_BACK, replies: 40 }), "with nothing of theirs, and the replies still counted");
  assert.ok(isTakenBack(root));
  assert.ok(!isTakenBack(rows[0]), "the control: one still theirs");
  assert.ok(!isTakenBack(row("3", { thread_name: THREAD_TAKEN_BACK })), "a thread somebody really called that, with its row");
  const protocol = readFileSync(join(import.meta.dirname, "../../../crates/voipc-protocol/src/types.rs"), "utf8");
  assert.ok(protocol.includes(`THREAD_TAKEN_BACK: &str = "${THREAD_TAKEN_BACK}"`), "the relay's own name for it");
});

test("a time no Date can hold is not drawn: the row's markup would throw", () => {
  for (const at_ms of [9e15, 2 ** 64, -9e15]) {
    assert.throws(() => new Date(at_ms).toISOString(), RangeError, "the control");
    const [held] = mergeArchiveRows([], [row("1", { at_ms })]);
    assert.doesNotThrow(() => new Date(held.at_ms).toISOString(), `${at_ms}`);
    assert.equal(held.at_ms, 0);
  }
  // The fixture holds a row from 2040: a far date is a date, and stays
  const far = Date.UTC(2040, 0, 1);
  assert.equal(mergeArchiveRows([], [row("1", { at_ms: far })])[0].at_ms, far);
});

test("what an operator's delete and someone's count come to, in words", () => {
  assert.equal(archiveDeletedLine(1204), "1,204 imported posts deleted.");
  assert.equal(archiveDeletedLine(1), "1 imported post deleted.");
  assert.match(archiveDeletedLine(0), /nothing was deleted/);
  assert.equal(mineDoneLine("Hide", 1204), "1,204 of your posts hidden.");
  assert.equal(mineDoneLine("Show", 3), "3 of your posts shown again.");
  assert.equal(mineDoneLine("Delete", 3), "3 of your posts deleted.");
  assert.equal(mineLine(0), "None of your posts came over from Discord.");
  assert.equal(mineLine(1), "1 of your posts is here from Discord.");
  assert.equal(mineLine(1204), "1,204 of your posts are here from Discord.");
});

test("an imported emote draws while it is listed, and stays words when it is not", () => {
  const emotes = [{ name: "pog", hash: "a".repeat(64), mime: "image/png", sticker: false } as never];
  assert.match(tokenize("look :pog: there", emotes), /<:pog:a+>/);
  assert.equal(tokenize("look :gone: there", emotes), "look :gone: there");
  // Inside code it stays as written, as importing left it
  assert.equal(tokenize("`:pog:`", emotes), "`:pog:`");
});

test("what importing writes for a file is words, with no link and no image", () => {
  const nodes = JSON.stringify(parse("[attachment: holiday.png]", { names: [] }));
  assert.doesNotMatch(nodes, /"t":"link"/);
  assert.equal(plainText("[attachment: holiday.png]"), "[attachment: holiday.png]");
});

test("nobody can be called on from an old post: no names, no mention", () => {
  const nodes = JSON.stringify(parse("@everyone look", { names: [] }));
  assert.doesNotMatch(nodes, /"t":"mention"/);
});
