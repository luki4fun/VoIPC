import { test } from "node:test";
import assert from "node:assert/strict";
import { BLOCKED_LINE, blockKey, blockMatch, foldedByBlock, foldedLine, isBlocked, newestUnfolded, silenceChanges } from "./block-rules.ts";
import { applyEvent, rowKey } from "./chat-rules.ts";
import type { ChatMessage } from "./types.ts";

const BOB = [...new Array(16).keys()].map((i) => i + 0xb0);
const BOB_HEX = BOB.map((x) => x.toString(16)).join("");
const CAROL = "cc".repeat(16);
const list = (...entries: [string, string][]) => new Map(entries);
const blockedBob = list([`a:${BOB_HEX}`, "bobby"]);
const blockedGuest = list(["g:eve#0001", "Eve#0001"]);
const msg = (more: Partial<ChatMessage> = {}): ChatMessage => ({ user_id: 5, username: "bobby", content: "hi", timestamp: 1, id: "m1", ...more });

test("a person is keyed by their account, or else by the name in lower case", () => {
  assert.equal(blockKey({ account: BOB, username: "bobby" }), `a:${BOB_HEX}`);
  assert.equal(blockKey({ account: BOB_HEX, username: "bobby" }), `a:${BOB_HEX}`, "a roster's bytes and a message's hex are one person");
  assert.equal(blockKey({ username: "Eve#0001" }), "g:eve#0001");
  // Browser wasm gives undefined for no account, the desktop null
  assert.equal(blockKey({ account: null, username: "Eve#0001" }), "g:eve#0001");
});

test("by account", () => {
  assert.ok(isBlocked(blockedBob, { account: BOB, username: "bobby" }, false));
  assert.ok(isBlocked(blockedBob, { account: BOB_HEX, username: "another name" }, false), "whatever they go by");
  assert.ok(!isBlocked(blockedBob, { account: CAROL, username: "carol" }, false));
});

test("by name for a guest, whichever way it is written", () => {
  assert.ok(isBlocked(blockedGuest, { username: "Eve#0001" }, false));
  assert.ok(isBlocked(blockedGuest, { username: "eve#0001" }, false));
  assert.ok(!isBlocked(blockedGuest, { username: "Eve#0002" }, false), "another tag is another name");
});

test("by name when a live message's account is unknown", () => {
  assert.ok(isBlocked(blockedBob, { username: "bobby" }, false));
  assert.equal(blockMatch(blockedBob, { username: "Bobby" }, false), `a:${BOB_HEX}`, "the entry to take back");
  assert.ok(!isBlocked(blockedBob, { username: "bobbie" }, false));
  assert.ok(!isBlocked(blockedBob, { username: "" }, false), "no name matches nothing");
  assert.ok(!isBlocked(list(["g:", ""]), { username: "" }, false));
});

test("a different account under a blocked guest's name is not blocked", () => {
  assert.ok(!isBlocked(blockedGuest, { account: CAROL, username: "Eve#0001" }, false));
  assert.ok(isBlocked(blockedGuest, { account: null, username: "Eve#0001" }, false), "the control: without the account it is");
});

test("nothing in an anonymous channel, whatever the row or the tag says", () => {
  const row = { account: BOB, username: "bobby" };
  assert.ok(!isBlocked(blockedBob, row, true));
  assert.ok(isBlocked(blockedBob, row, false), "the control: the same row elsewhere");
  assert.ok(!isBlocked(blockedGuest, { username: "Eve#0001" }, true));
});

test("a message folds until it is shown, and stays one row through an event", () => {
  const m = msg({ account: BOB_HEX });
  assert.ok(foldedByBlock(blockedBob, m, false, new Set()));
  assert.ok(!foldedByBlock(blockedBob, m, true, new Set()), "not in an anonymous channel");
  assert.ok(!foldedByBlock(new Map(), m, false, new Set()), "unblocked, it is back");
  const shown = new Set([rowKey(m)]);
  assert.ok(!foldedByBlock(blockedBob, m, false, shown));
  // Their reaction made a new object of it: still the row they asked to see
  const reacted = applyEvent([m], {
    event: { kind: "react", target: "m1", emoji: "🔥", on: true },
    by: { user_id: 6, username: "carol", account: CAROL },
    at: 2,
    content: "",
  }, { mayPin: false, current: () => true })[0];
  assert.notEqual(reacted, m);
  assert.ok(!foldedByBlock(blockedBob, reacted, false, shown));
});

test("a member's copy of what they said folds too, by the name it gives", () => {
  assert.ok(foldedByBlock(blockedBob, msg({ kind: "shared" }), false, new Set()));
});

test("a line of our own or a tombstone never folds", () => {
  for (const kind of ["notice", "history-marker", "deleted"] as const) {
    assert.ok(!foldedByBlock(blockedBob, msg({ kind, account: BOB_HEX }), false, new Set()), kind);
  }
  assert.equal(BLOCKED_LINE, "Message from someone you blocked");
});

const row = (user_id: number, account?: number[] | null, username = "someone") => ({ user_id, account, username });

test("somebody blocked in the room is silenced, and that is the end of it", () => {
  const people = [row(5, BOB, "bobby"), row(6, null, "carol#0001")];
  assert.deepEqual(silenceChanges(people, blockedBob, false, new Set()), [{ id: 5, on: true }]);
  assert.deepEqual(silenceChanges(people, blockedBob, false, new Set([5])), [], "unchanged input yields nothing");
});

test("a new id for the same account is silenced", () => {
  const back = [row(9, BOB, "bobby")];
  assert.deepEqual(silenceChanges(back, blockedBob, false, new Set()), [{ id: 9, on: true }]);
  // Both at once, as a reconnect shows up: the old id given back, the new one silenced
  assert.deepEqual(silenceChanges(back, blockedBob, false, new Set([5])), [
    { id: 9, on: true },
    { id: 5, on: false },
  ]);
});

test("a row in an anonymous room is restored", () => {
  const people = [row(5, BOB, "bobby")];
  assert.deepEqual(silenceChanges(people, blockedBob, true, new Set([5])), [{ id: 5, on: false }]);
  assert.deepEqual(silenceChanges(people, blockedBob, true, new Set()), [], "and never silenced there");
  assert.deepEqual(silenceChanges(people, blockedBob, false, new Set()), [{ id: 5, on: true }], "the control");
});

test("an unblock restores", () => {
  assert.deepEqual(silenceChanges([row(5, BOB, "bobby")], new Map(), false, new Set([5])), [{ id: 5, on: false }]);
});

test("somebody who left is given back: their id means nobody now", () => {
  assert.deepEqual(silenceChanges([], blockedBob, false, new Set([5])), [{ id: 5, on: false }]);
});

test("a guest is silenced by the name", () => {
  assert.deepEqual(silenceChanges([row(7, undefined, "Eve#0001")], blockedGuest, false, new Set()), [{ id: 7, on: true }]);
});

test("someone blocked brings no news, and what they wrote does not hide what others did", () => {
  const anna = msg({ username: "anna", timestamp: 5, id: "a" });
  const bobs = msg({ account: BOB_HEX, timestamp: 9, id: "b" });
  const shown = new Set<ChatMessage>();
  assert.equal(newestUnfolded(blockedBob, [anna, bobs], false, shown), 5);
  assert.equal(newestUnfolded(blockedBob, [bobs, anna], false, shown), 5, "the last that shows, not the highest stamp");
  assert.equal(newestUnfolded(blockedBob, [bobs], false, shown), 0, "nothing else there");
  assert.equal(newestUnfolded(blockedBob, [], false, shown), 0);
  // The controls: each of these leaves the row showing, so it counts
  assert.equal(newestUnfolded(list(), [anna, bobs], false, shown), 9, "nobody blocked");
  assert.equal(newestUnfolded(blockedBob, [anna, bobs], true, shown), 9, "an anonymous channel");
  assert.equal(newestUnfolded(blockedBob, [anna, bobs], false, new Set([rowKey(bobs)])), 9, "shown anyway");
});

test("a row says what a moderator did before who wrote it, and shows on one Show", () => {
  const nobody = list();
  const shown = new Set<ChatMessage>();
  const plain = msg({ account: BOB_HEX });
  const hidden = { ...plain, hide: { on: true, at: 2, by: "kim#0001" } };
  assert.equal(foldedLine(nobody, plain, false, shown), null);
  assert.equal(foldedLine(blockedBob, plain, false, shown), BLOCKED_LINE);
  assert.equal(foldedLine(nobody, hidden, false, shown), "Removed by kim");
  assert.equal(foldedLine(blockedBob, hidden, false, shown), "Removed by kim");
  assert.equal(foldedLine(blockedBob, hidden, false, new Set([rowKey(hidden)])), null);
  // Restored, it is only what it was
  const restored = { ...plain, hide: { on: false, at: 3, by: "kim#0001" } };
  assert.equal(foldedLine(nobody, restored, false, shown), null);
  assert.equal(foldedLine(blockedBob, restored, false, shown), BLOCKED_LINE);
});
