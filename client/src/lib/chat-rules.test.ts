// The two rules that make shared chat history safe to merge: an id decides
// what is the same message, and a deletion is not undone by somebody else's
// copy. Both matter most in the case the feature exists for — three people
// holding three overlapping parts of one conversation.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  isLegacyDmKey,
  mergeHistory,
  newestTimestamp,
  plausibleTimestamp,
  pruneConversations,
  MAX_CONVERSATIONS,
  MAX_MESSAGE_TTL_SECS,
  dropExpired,
  expiryFor,
  hasExpired,
  soonerExpiry,
  sanitizeHistory,
} from "./chat-rules.ts";
import type { ChatMessage } from "./types.ts";

const T = 1_700_000_000_000;

function msg(over: Partial<ChatMessage> & { timestamp: number }): ChatMessage {
  return { user_id: 1, username: "alice", content: "hello", ...over };
}

test("a message offered twice is stored once", () => {
  const mine = [msg({ timestamp: T, id: "a" })];
  const theirs = [msg({ timestamp: T + 5, id: "a" })];
  const { messages, added } = mergeHistory(mine, theirs, "bob");
  assert.equal(added, 0);
  assert.deepEqual(messages, mine, "nothing changes, not even a divider");
});

test("two different messages that read alike both survive when they have ids", () => {
  // The old heuristic would have collapsed these: same author, same text,
  // seconds apart. The ids say they are two.
  const mine = [msg({ timestamp: T, id: "a" })];
  const theirs = [msg({ timestamp: T + 5, id: "b" })];
  const { added } = mergeHistory(mine, theirs, "bob");
  assert.equal(added, 1);
});

test("without ids the old heuristic still catches a duplicate", () => {
  // Anything stored before this release has no id, and the first share after
  // upgrading must not double the whole conversation.
  const mine = [msg({ timestamp: T })];
  const theirs = [msg({ timestamp: T + 60_000 })];
  assert.equal(mergeHistory(mine, theirs, "bob").added, 0);
  // Far enough apart, it is somebody saying the same thing again
  assert.equal(mergeHistory(mine, [msg({ timestamp: T + 200_000 })], "bob").added, 1);
});

test("a mixed pair still collapses: one side has an id, the other does not", () => {
  const mine = [msg({ timestamp: T })];
  const theirs = [msg({ timestamp: T + 1000, id: "a" })];
  assert.equal(mergeHistory(mine, theirs, "bob").added, 0);
});

test("three people's halves become one conversation in order", () => {
  const mine = [msg({ timestamp: T + 300, content: "c", id: "c" })];
  const fromBob = [
    msg({ timestamp: T + 100, content: "a", id: "a" }),
    msg({ timestamp: T + 200, content: "b", id: "b" }),
  ];
  const fromCarol = [
    msg({ timestamp: T + 200, content: "b", id: "b" }),
    msg({ timestamp: T + 250, content: "b2", id: "b2" }),
  ];

  let { messages } = mergeHistory(mine, fromBob, "bob");
  ({ messages } = mergeHistory(messages, fromCarol, "carol"));

  const text = messages.filter((m) => m.kind !== "history-marker").map((m) => m.content);
  assert.deepEqual(text, ["a", "b", "b2", "c"]);
  // One divider per hand-off that brought something
  assert.equal(messages.filter((m) => m.kind === "history-marker").length, 2);
});

test("what was deleted here is not handed back", () => {
  const cleared = newestTimestamp([msg({ timestamp: T + 200, id: "b" })]);
  const offered = [
    msg({ timestamp: T + 100, content: "old", id: "a" }),
    msg({ timestamp: T + 200, content: "also old", id: "b" }),
    msg({ timestamp: T + 300, content: "after the delete", id: "c" }),
  ];
  const { messages, added } = mergeHistory([], offered, "bob", cleared);
  assert.equal(added, 1);
  assert.deepEqual(
    messages.filter((m) => m.kind !== "history-marker").map((m) => m.content),
    ["after the delete"],
  );

  // ...until the user asks for it back, which drops the watermark
  assert.equal(mergeHistory([], offered, "bob", 0).added, 3);
});

test("a merge that adds nothing leaves no divider behind", () => {
  const mine = [msg({ timestamp: T, id: "a" })];
  const { messages } = mergeHistory(mine, [msg({ timestamp: T, id: "a" })], "bob");
  assert.equal(messages.filter((m) => m.kind === "history-marker").length, 0);
});

test("asking the same person twice moves their divider rather than stacking one", () => {
  const first = mergeHistory([], [msg({ timestamp: T, id: "a" })], "bob").messages;
  assert.equal(first.filter((m) => m.kind === "history-marker").length, 1);
  const again = mergeHistory(first, [msg({ timestamp: T + 10, id: "b" })], "bob").messages;
  const markers = again.filter((m) => m.kind === "history-marker");
  assert.equal(markers.length, 1);
  assert.equal(markers[0].timestamp, T + 10, "it follows the newest thing bob brought");
});

test("a conversation stays capped however much is poured into it", () => {
  const many = Array.from({ length: 600 }, (_, i) =>
    msg({ timestamp: T + i, content: `m${i}`, id: `id${i}` }),
  );
  const { messages } = mergeHistory(many, [msg({ timestamp: T + 9999, id: "last" })], "bob");
  assert.equal(messages.length, 500);
  assert.equal(messages[messages.length - 1].id, undefined, "the divider sits last");
});

test("a peer cannot put anything it likes into our archive", () => {
  const cleaned = sanitizeHistory([
    null,
    { user_id: "1", username: "x", content: "y", timestamp: T },
    { user_id: 1, username: "x", content: "y", timestamp: "soon" },
    { user_id: 1, username: "x", content: "y", timestamp: Number.NaN },
    { user_id: 2, username: "b".repeat(80), content: "c".repeat(5000), timestamp: T, kind: "text" },
    { user_id: 3, username: "ok", content: "fine", timestamp: T, kind: "image", id: "z".repeat(200) },
  ]);
  assert.equal(cleaned.length, 2);
  assert.equal(cleaned[0].username.length, 32);
  assert.equal(cleaned[0].content.length, 2000);
  assert.equal(cleaned[0].kind, "shared", 'a claim of "text" is still second-hand');
  assert.equal(cleaned[1].kind, "shared", "and so is a claim of anything else");
  assert.equal(cleaned[1].id?.length, 64);
});

test("shared history is marked second-hand and stays second-hand", () => {
  const offered = [{ user_id: 1, username: "alice", content: "hello", timestamp: T, id: "a" }];
  assert.deepEqual(sanitizeHistory(offered).map((m) => m.kind), ["shared"]);

  // What we pass on to the next person to join comes back through here on their
  // side: relaying a conversation is how it survives its last original witness,
  // and it must not become first-hand on the way.
  assert.deepEqual(sanitizeHistory(sanitizeHistory(offered)).map((m) => m.kind), ["shared"]);

  // The mark is also what a peer cannot talk its way out of: one of our own
  // dividers, claimed rather than drawn by us, is just another shared message.
  const forged = sanitizeHistory([
    { user_id: 0, username: "", content: "Earlier messages shared by bob", timestamp: T, kind: "history-marker" },
  ]);
  assert.deepEqual(forged.map((m) => m.kind), ["shared"]);
});

test("a first-hand copy wins over a shared one", () => {
  const shared = sanitizeHistory([
    { user_id: 1, username: "alice", content: "hello", timestamp: T, id: "a" },
  ]);
  const { messages, added } = mergeHistory(shared, [msg({ timestamp: T, id: "a" })], "bob");
  assert.equal(added, 0, "it is the same message, not a second one");
  assert.deepEqual(messages.map((m) => m.kind), [undefined], "and we saw this one ourselves");

  // Never the other way round, or provenance could be washed off by asking
  // somebody to hand us back a message we already have.
  const mine = [msg({ timestamp: T, id: "a" })];
  assert.deepEqual(mergeHistory(mine, shared, "bob").messages.map((m) => m.kind), [undefined]);
});

test("two members cannot shadow each other by squatting a message id", () => {
  // Ids are inside the ciphertext, so the server cannot see them — but every
  // member of the channel can, and offering a history under somebody else's id
  // is how one of them would hide what that person actually wrote.
  const mine = [msg({ user_id: 1, timestamp: T, content: "what alice wrote", id: "x" })];
  const theirs = [
    msg({ user_id: 2, username: "mallory", timestamp: T + 1, content: "what mallory says", id: "x" }),
  ];
  const { messages, added } = mergeHistory(mine, theirs, "mallory");
  assert.equal(added, 1);
  assert.deepEqual(
    messages.filter((m) => m.kind !== "history-marker").map((m) => m.content),
    ["what alice wrote", "what mallory says"],
  );
});

test("a far-future timestamp cannot become a watermark", () => {
  const now = T;
  // One of these plus one channel clear would otherwise bury every message the
  // user is ever offered again, with nothing on screen to say why.
  assert.equal(newestTimestamp([msg({ timestamp: T - 1000 }), msg({ timestamp: 1e308 })], now), T - 1000);
  assert.deepEqual(sanitizeHistory([{ user_id: 1, username: "a", content: "y", timestamp: 1e308 }]), []);

  assert.equal(plausibleTimestamp(0), false);
  assert.equal(plausibleTimestamp(-1), false);
  assert.equal(plausibleTimestamp(now + 25 * 60 * 60 * 1000, now), false);
  assert.equal(plausibleTimestamp(now + 60 * 60 * 1000, now), true, "a clock an hour out is a clock");
});

test("the number of conversations is capped, to whatever the user set", () => {
  const map = new Map<string, ChatMessage[]>();
  for (let i = 0; i < 250; i++) map.set(`host:1/c${i}`, [msg({ timestamp: T + i })]);
  const pruned = pruneConversations(map, 200);
  assert.equal(pruned.size, 200);
  assert.equal(pruned.has("host:1/c249"), true, "the one written in last stays");
  assert.equal(pruned.has("host:1/c0"), false, "the one nobody has touched goes first");

  // Under the cap it is the same map, so a save copies nothing it need not
  const few = new Map([["host:1/general", [msg({ timestamp: T })]]]);
  assert.equal(pruneConversations(few), few);

  // The default is generous, because what this costs is a larger map to write
  // out and what it drops is somebody's own archive.
  assert.equal(pruneConversations(map).size, 250);
  assert.equal(MAX_CONVERSATIONS, 1000);

  // And 0 is an answer: keep everything.
  assert.equal(pruneConversations(map, 0), map);
  assert.equal(pruneConversations(map, -1), map);

  // A cap of two keeps the two most recently written in
  const two = pruneConversations(map, 2);
  assert.deepEqual([...two.keys()].sort(), ["host:1/c248", "host:1/c249"]);
});

test("a placeholder for ciphertext a sharer could not open is not taken", () => {
  const cleaned = sanitizeHistory([
    { user_id: 1, username: "a", content: "real", timestamp: T },
    {
      user_id: 2,
      username: "b",
      content: "[encrypted message — decryption failed]",
      timestamp: T + 1,
      kind: "undecryptable",
    },
  ]);
  assert.deepEqual(cleaned.map((m) => m.content), ["real"]);
});

test("however much is offered, only the last fifty are taken", () => {
  const offered = Array.from({ length: 200 }, (_, i) => ({
    user_id: 1,
    username: "a",
    content: `m${i}`,
    timestamp: T + i,
  }));
  const cleaned = sanitizeHistory(offered);
  assert.equal(cleaned.length, 50);
  assert.equal(cleaned[0].content, "m150");
});

test("an empty conversation has no watermark to set", () => {
  assert.equal(newestTimestamp([]), 0);
  assert.equal(newestTimestamp([msg({ timestamp: T }), msg({ timestamp: T + 5 })]), T + 5);
});

test("a conversation filed under two user ids is not read back", () => {
  // Ids are handed out per connection and reused, so "1-2" names a different
  // pair of people every day and on every server.
  assert.ok(isLegacyDmKey("1-2"));
  assert.ok(isLegacyDmKey("17-1200"));
  assert.ok(!isLegacyDmKey("chat.example.com:9987/alice"));
  assert.ok(!isLegacyDmKey("alice"));
  // A name that merely looks numeric is still a name, because it is scoped
  assert.ok(!isLegacyDmKey("host:9987/1-2"));
});

// ── Message destruction timers ─────────────────────────────────────────────

test("a deadline is the shorter of what the sender claims and what the channel says", () => {
  // Nothing at all: the message has no timer.
  assert.equal(expiryFor(T), undefined);
  // The sender's own, where the channel has none.
  assert.equal(expiryFor(T, 60), T + 60_000);
  // The channel's, where the message claims none — which is what stops a
  // member re-sharing a message from keeping it alive by dropping the field.
  assert.equal(expiryFor(T, undefined, 60), T + 60_000);
  // Both: the shorter wins, whichever side it comes from.
  assert.equal(expiryFor(T, 3600, 60), T + 60_000);
  assert.equal(expiryFor(T, 60, 3600), T + 60_000);
  // Counted from the message's own timestamp, not from now, so every copy of
  // one message names the same instant.
  assert.equal(expiryFor(T - 50_000, 60), T + 10_000);
  // Zero and nonsense are "no timer", not "delete on arrival".
  assert.equal(expiryFor(T, 0, 0), undefined);
  assert.equal(expiryFor(T, -5), undefined);
  assert.equal(expiryFor(T, Number.NaN), undefined);
  // A year is "never" written as a number, so it is cut down where it enters.
  assert.equal(expiryFor(T, 10 * 365 * 24 * 3600), T + MAX_MESSAGE_TTL_SECS * 1000);
});

test("a shared copy can bring a deletion forward and never push it back", () => {
  const mine = msg({ id: "m1", user_id: 1, timestamp: T, expires_at: T + 60_000 });
  // The same message, offered by somebody claiming it lives a week
  const theirs = { ...mine, kind: "shared", expires_at: T + 7 * 24 * 3600_000 };
  // An explicit clock: these deadlines are around a fixed timestamp, and a
  // hand-off is refused outright once its messages are past their moment.
  const now = T + 1;
  const later = mergeHistory([mine], sanitizeHistory([theirs], undefined, now), "bob");
  assert.equal(later.messages[0].expires_at, T + 60_000, "their claim did not extend ours");

  // ...and the other way round: a copy that dies sooner takes ours with it
  const sooner = { ...mine, kind: "shared", expires_at: T + 1_000 };
  const earlier = mergeHistory([mine], sanitizeHistory([sooner], undefined, now), "bob");
  assert.equal(earlier.messages[0].expires_at, T + 1_000);
  assert.equal(soonerExpiry(undefined, 5), 5);
  assert.equal(soonerExpiry(5, undefined), 5);
});

test("the channel's timer applies to history whose timer was stripped", () => {
  const stripped = { user_id: 1, username: "a", content: "secret", timestamp: T };
  const now = T + 1;
  const [taken] = sanitizeHistory([stripped], 60, now);
  assert.equal(taken.expires_at, T + 60_000, "a claim of 'no timer' does not beat the channel");

  // And a sharer cannot name a date beyond what the channel allows
  const generous = { ...stripped, expires_at: T + 7 * 24 * 3600_000 };
  const [clamped] = sanitizeHistory([generous], 60, now);
  assert.equal(clamped.expires_at, T + 60_000);
});

test("a message whose moment has passed is not taken as history", () => {
  const now = T + 120_000;
  const gone = { user_id: 1, username: "a", content: "gone", timestamp: T, expires_at: T + 60_000 };
  const live = { user_id: 1, username: "a", content: "here", timestamp: T, expires_at: now + 60_000 };
  const taken = sanitizeHistory([gone, live], undefined, now);
  assert.equal(taken.length, 1);
  assert.equal(taken[0].content, "here");

  // The same, where it is the channel's timer that has run out on it
  assert.equal(sanitizeHistory([{ ...gone, expires_at: undefined }], 60, now).length, 0);
});

test("a sweep drops what is due and leaves the rest alone", () => {
  const now = T + 10_000;
  const list = [
    msg({ content: "no timer", timestamp: T }),
    msg({ content: "due", timestamp: T, expires_at: now - 1 }),
    msg({ content: "later", timestamp: T, expires_at: now + 1 }),
  ];
  assert.equal(hasExpired(list[1], now), true);
  assert.equal(hasExpired(list[0], now), false);

  const swept = dropExpired(list, now);
  assert.deepEqual(swept.map((m) => m.content), ["no timer", "later"]);
  // Nothing due: the same array back, so a sweep over a quiet app re-renders
  // nothing at all.
  assert.equal(dropExpired(swept, now), swept);
});
