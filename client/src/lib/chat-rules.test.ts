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
  messageRefs,
  toArchived,
  fromArchived,
  fileRef,
  applyEvent,
  chatEvent,
  forHandOff,
  cutText,
  forwarded,
  isOneEmoji,
  pinnedOf,
  reactionChips,
  rowKey,
  sameRow,
  MAX_REACTION_EMOJI,
  MAX_REACTORS,
  MAX_RECEIVED_BYTES,
  notificationBody,
  receivedText,
  type EventIn,
} from "./chat-rules.ts";
import type { ChatMessage } from "./types.ts";
import { EMOJI_CATEGORIES, QUICK_REACTIONS } from "./emoji.ts";

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

test("between accounts the account is the author, not this connection's user id", () => {
  // Read live as user 7, then again from the stored log after a reconnect,
  // where the same person is user 12: one message.
  const live = [msg({ timestamp: T, id: "a", user_id: 7, account: "aa" })];
  const stored = [msg({ timestamp: T, id: "a", user_id: 12, account: "aa" })];
  assert.equal(mergeHistory(live, stored, "").added, 0);
  // Somebody else's account using that id is somebody else's message.
  assert.equal(mergeHistory(live, [msg({ timestamp: T, id: "a", user_id: 7, account: "bb" })], "").added, 1);
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
  assert.equal(cleaned[0].username.length, 37, "a name and its tag");
  assert.equal(cleaned[0].content.length, 2000);
  assert.equal(cleaned[0].kind, "shared", 'a claim of "text" is still second-hand');
  assert.equal(cleaned[1].kind, "shared", "and so is a claim of anything else");
  assert.equal(cleaned[1].id?.length, 64);
});

test("what a shared message answers comes along, bounded like an id", () => {
  const [kept] = sanitizeHistory([
    { user_id: 1, username: "ann", content: "agreed", timestamp: T, id: "b", reply_to: "a", thread: "z".repeat(200) },
  ]);
  assert.equal(kept.reply_to, "a");
  assert.equal(kept.thread?.length, 64);
  const [plain] = sanitizeHistory([{ user_id: 1, username: "ann", content: "hi", timestamp: T, reply_to: "", thread: 7 }]);
  assert.ok(!("reply_to" in plain) && !("thread" in plain), "nothing claimed, nothing kept");
});

test("a live message's refs are kept only where there are some", () => {
  assert.deepEqual(messageRefs({ reply_to: "a", thread: null }), { reply_to: "a" });
  assert.deepEqual(messageRefs({}), {});
  assert.deepEqual(messageRefs({ reply_to: 5, thread: ["x"] }), {});
});

test("the archive keeps newer fields in extra and gives them back", () => {
  const reply = msg({ timestamp: T, id: "b", reply_to: "a", thread: "a" });
  const stored = toArchived(reply);
  assert.equal(stored.extra, JSON.stringify({ reply_to: "a", thread: "a" }));
  assert.ok(!("reply_to" in stored), "folded in, not written twice");
  assert.deepEqual(fromArchived(stored), reply);
  const plain = msg({ timestamp: T, id: "c" });
  assert.ok(!("extra" in toArchived(plain)), "a plain message stays a plain one");
  // serde's nulls, and an extra that is not ours to trust blindly
  const back = fromArchived({ ...plain, kind: null as unknown as undefined, extra: '{"reply_to":"' + "x".repeat(99) + '"}' });
  assert.equal(back.reply_to?.length, 64);
  assert.ok(!("kind" in back));
  assert.deepEqual(fromArchived({ ...plain, extra: "{not json" }), plain, "a damaged extra loses only itself");
});

test("a file comes back from the archive only as a file that can be fetched", () => {
  const file = { hash: "a".repeat(64), key: "b".repeat(64), size: 3, z: false, name: "a.txt" };
  const sent = msg({ timestamp: T, id: "f", file });
  assert.deepEqual(fromArchived(toArchived(sent)), sent);
  const plain = msg({ timestamp: T, id: "g" });
  for (const bad of [{ ...file, hash: "A".repeat(64) }, { ...file, key: "b" }, { ...file, size: -1 }, { ...file, size: 2 ** 27 }, { ...file, z: 1 }, "x"]) {
    assert.deepEqual(fromArchived({ ...plain, extra: JSON.stringify({ file: bad }) }), plain, JSON.stringify(bad));
  }
  const more = fromArchived({ ...plain, extra: JSON.stringify({ file: { ...file, evil: "<b>" } }) });
  assert.deepEqual(more.file, file, "only the fields that are checked");
});

test("a file's claims are bounded as envelope.rs bounds them", () => {
  const blob = { hash: "a".repeat(64), key: "b".repeat(64), size: 3, z: true };
  // No name is "file"; a name is cleaned of control and direction characters
  assert.equal(fileRef(blob)?.name, "file");
  const name = fileRef({ ...blob, name: "\u202egpj.exe\n" + "x".repeat(300) })!.name;
  assert.equal(Array.from(name).length, 255);
  assert.ok(name.startsWith("gpj.exex"));
  assert.equal(fileRef({ ...blob, name: " \u0007 " })?.name, "file");
  // What is out of bounds goes; the file stays
  const out = fileRef({ ...blob, mime: "text/html; x", w: 16_385, h: 0, dur: -1, px: "A".repeat(1023) })!;
  assert.deepEqual(Object.keys(out).sort(), ["hash", "key", "name", "size", "z"]);
  const kept = fileRef({ ...blob, mime: "Image/PNG", w: 640, h: 480, dur: 0, px: "A".repeat(1024) })!;
  assert.deepEqual([kept.mime, kept.w, kept.h, kept.dur, kept.px?.length], ["image/png", 640, 480, 0, 1024]);
});

test("a file survives the history hand-off, checked", () => {
  const file = { hash: "c".repeat(64), key: "d".repeat(64), size: 9, z: false, name: "pic.webp", w: 8, h: 8 };
  const [shared] = sanitizeHistory([{ user_id: 1, username: "ann", content: "look", timestamp: T, file }], null, T);
  assert.deepEqual(shared.file, file);
  const [bad] = sanitizeHistory([{ user_id: 1, username: "ann", content: "x", timestamp: T, file: { ...file, key: "z" } }], null, T);
  assert.ok(!("file" in bad));
});

test("history that is not a list offers nothing instead of throwing", () => {
  for (const offered of [{}, null, "x", 3, { length: 2 }]) {
    assert.deepEqual(sanitizeHistory(offered), []);
  }
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

// ── Edit, delete, reactions, pins (1.3) ─────────────────────────────────────

const ann = { user_id: 1, username: "ann#0001", account: "aa" };
const ben = { user_id: 2, username: "ben#0002", account: "bb" };
const guest = { user_id: 3, username: "cy#0003" };

function ev(event: EventIn["event"], by: EventIn["by"], at: number, content = ""): EventIn {
  return { event, by, at, content };
}

const conv = () => [
  msg({ timestamp: T, id: "m1", ...ann, content: "first", expires_at: T + 3_600_000 }),
  msg({ timestamp: T + 1, id: "m2", ...ben, content: "second" }),
  msg({ timestamp: T + 2, id: "m3", ...guest, content: "third" }),
];

test("an edit applies only from the message's writer, and marks it edited", () => {
  const list = conv();
  const edited = applyEvent(list, ev({ kind: "edit", target: "m1" }, ann, T + 10, "first, fixed"), { mayPin: false });
  assert.equal(edited[0].content, "first, fixed");
  assert.equal(edited[0].edited_at, T + 10);
  assert.equal(edited[0].expires_at, T + 3_600_000, "an edit never extends the timer");
  assert.ok(sameRow(edited[0], list[0]), "the same row on screen");
  assert.equal(edited[1], list[1], "the rest are the same objects");
  // Somebody else's edit of it, with the same id: nothing
  assert.equal(applyEvent(list, ev({ kind: "edit", target: "m1" }, ben, T + 10, "hijacked"), { mayPin: false }), list);
  // The same name on another account is somebody else
  assert.equal(applyEvent(list, ev({ kind: "edit", target: "m1" }, { ...ann, account: "zz" }, T + 10, "x"), { mayPin: false }), list);
  // An older edit arriving late (the stored log after the live one) changes nothing
  assert.equal(applyEvent(edited, ev({ kind: "edit", target: "m1" }, ann, T + 5, "older"), { mayPin: false }), edited);
  assert.equal(applyEvent(list, ev({ kind: "edit", target: "nope" }, ann, T + 10, "x"), { mayPin: false }), list);
});

test("a guest edits by user id and name, so only within their session", () => {
  const list = conv();
  assert.equal(applyEvent(list, ev({ kind: "edit", target: "m3" }, guest, T + 9, "third!"), { mayPin: false })[2].content, "third!");
  // Reconnected under a new id: their messages stay as sent
  assert.equal(applyEvent(list, ev({ kind: "edit", target: "m3" }, { ...guest, user_id: 9 }, T + 9, "x"), { mayPin: false }), list);
  // An account holder with the guest's id and name is not the guest
  assert.equal(applyEvent(list, ev({ kind: "edit", target: "m3" }, { ...guest, account: "cc" }, T + 9, "x"), { mayPin: false }), list);
});

test("a delete leaves a tombstone that a hand-off or the stored log cannot bring back", () => {
  const list = conv();
  list[0] = { ...list[0], file: fileRef({ hash: "a".repeat(64), key: "b".repeat(64), size: 1, z: false, name: "x" })!, reply_to: "r" };
  const gone = applyEvent(list, ev({ kind: "delete", target: "m1" }, ann, T + 10), { mayPin: false });
  assert.deepEqual(gone[0], { user_id: 1, username: "ann#0001", account: "aa", content: "", timestamp: T, id: "m1", kind: "deleted", expires_at: T + 3_600_000 });
  assert.equal(applyEvent(list, ev({ kind: "delete", target: "m1" }, ben, T + 10), { mayPin: false }), list, "only its writer");
  // The same message offered again: by the stored log (first-hand), by a member (hearsay)
  const again = mergeHistory(gone, [msg({ timestamp: T, id: "m1", ...ann, content: "first" })], "");
  assert.equal(again.added, 0);
  assert.equal(again.messages[0].kind, "deleted");
  const shared = sanitizeHistory([{ ...list[0], user_id: 1, username: "ann#0001" }]);
  assert.equal(mergeHistory(gone.map(({ account: _, ...m }) => m), shared, "ben").added, 0);
  // Nothing more is done to what is gone
  assert.equal(applyEvent(gone, ev({ kind: "edit", target: "m1" }, ann, T + 20, "back"), { mayPin: false }), gone);
  assert.equal(applyEvent(gone, ev({ kind: "react", target: "m1", emoji: "👍", on: true }, ben, T + 20), { mayPin: false }), gone);
  // And it survives the archive as what it is
  assert.equal(fromArchived(toArchived(gone[0])).kind, "deleted");
});

test("reactions: the latest event per person and emoji wins", () => {
  let list = conv();
  const thumbs = (by: EventIn["by"], on: boolean, at: number) =>
    (list = applyEvent(list, ev({ kind: "react", target: "m2", emoji: "👍", on }, by, at), { mayPin: false }));
  thumbs(ann, true, T + 10);
  thumbs(guest, true, T + 11);
  assert.deepEqual(reactionChips(list[1], (k) => k === "a:aa"), [{ emoji: "👍", count: 2, mine: true, names: ["ann#0001", "cy#0003"] }]);
  thumbs(ann, false, T + 12);
  assert.deepEqual(reactionChips(list[1], (k) => k === "a:aa"), [{ emoji: "👍", count: 1, mine: false, names: ["cy#0003"] }]);
  const before = list;
  thumbs(ann, true, T + 11);
  assert.equal(list, before, "an older 'on' after a newer 'off' changes nothing");
  // A second person's off for a reaction they never made changes nothing
  thumbs(ben, false, T + 13);
  assert.equal(list, before);
  // Reacting twice is still one
  thumbs(guest, true, T + 14);
  assert.equal(reactionChips(list[1], () => false)[0].count, 1);
});

test("reactions: at most twenty different emoji on a message, and a bounded record", () => {
  let list = conv();
  const pictures = [..."😀😁😂🤣😃😄😅😆😉😊😎🤩😏😒😞😔😟😕😣😖😫😩"];
  pictures.forEach((emoji, i) => {
    list = applyEvent(list, ev({ kind: "react", target: "m1", emoji, on: true }, ben, T + i), { mayPin: false });
  });
  assert.equal(reactionChips(list[0], () => false).length, MAX_REACTION_EMOJI);
  // One taken off makes room for another
  list = applyEvent(list, ev({ kind: "react", target: "m1", emoji: "😀", on: false }, ben, T + 50), { mayPin: false });
  list = applyEvent(list, ev({ kind: "react", target: "m1", emoji: "🔥", on: true }, ann, T + 51), { mayPin: false });
  assert.ok(reactionChips(list[0], () => false).some((c) => c.emoji === "🔥"));
  // People per emoji are bounded
  for (let i = 0; i < MAX_REACTORS + 5; i++) {
    list = applyEvent(list, ev({ kind: "react", target: "m2", emoji: "👍", on: true }, { user_id: 100 + i, username: `g${i}` }, T + i), { mayPin: false });
  }
  assert.equal(reactionChips(list[1], () => false)[0].count, MAX_REACTORS);
});

test("a pin counts only from a manager, and the latest pin event wins", () => {
  const list = conv();
  const pin = (on: boolean, at: number, mayPin: boolean, l = list) =>
    applyEvent(l, ev({ kind: "pin", target: "m2", on }, ann, at), { mayPin });
  assert.equal(pin(true, T + 10, false), list, "a member's pin is nothing");
  const pinned = pin(true, T + 10, true);
  assert.deepEqual(pinned[1].pin, { on: true, at: T + 10, by: "ann#0001" });
  assert.deepEqual(pinnedOf(pinned).map((m) => m.id), ["m2"]);
  const unpinned = pin(false, T + 20, true, pinned);
  assert.deepEqual(pinnedOf(unpinned), []);
  assert.equal(pin(true, T + 15, true, unpinned), unpinned, "an older pin after a newer unpin");
  // Pins and reactions survive a reload, checked; a hand-off carries neither
  const back = fromArchived(toArchived(pinned[1]));
  assert.deepEqual(back.pin, pinned[1].pin);
  assert.equal(forHandOff(pinned[1]).pin, undefined);
  assert.equal(sanitizeHistory([pinned[1]])[0].pin, undefined, "nor does a receiver take one");
});

test("what events did is checked again when the archive is read", () => {
  const stored = toArchived(
    msg({
      timestamp: T,
      id: "m",
      edited_at: T + 5,
      reactions: [
        { emoji: "👍", by: [{ key: "a:aa", name: "ann", on: true, at: T + 1 }, { key: "a:aa", name: "dup", on: true, at: T + 2 }] },
        { emoji: "not one", by: [{ key: "a:bb", name: "ben", on: true, at: T + 1 }] },
        { emoji: "🔥", by: [{ key: 7, name: "x", on: true, at: T }] },
      ] as never,
      pin: { on: true, at: -1, by: "ann" },
    }),
  );
  const back = fromArchived(stored);
  assert.equal(back.edited_at, T + 5);
  assert.deepEqual(back.reactions, [{ emoji: "👍", by: [{ key: "a:aa", name: "ann", on: true, at: T + 1 }] }]);
  assert.equal(back.pin, undefined);
  assert.equal(fromArchived(toArchived(msg({ timestamp: T, edited_at: T - 1 }))).edited_at, undefined, "edited before it was written");
});

test("an event is acted on only whole, and a reaction is one emoji", () => {
  assert.deepEqual(chatEvent({ kind: "react", target: "m", emoji: "👍🏽", on: true }), { kind: "react", target: "m", emoji: "👍🏽", on: true });
  assert.deepEqual(chatEvent({ kind: "edit", target: "x".repeat(100) }), { kind: "edit", target: "x".repeat(64) });
  for (const bad of [
    null,
    { kind: "edit" },
    { kind: "delete", target: "" },
    { kind: "react", target: "m", emoji: "👍" },
    { kind: "react", target: "m", emoji: "👍👍", on: true },
    { kind: "pin", target: "m", on: 1 },
    { kind: "purge", target: "m" },
  ]) {
    assert.equal(chatEvent(bad), undefined, JSON.stringify(bad));
  }
  for (const one of ["👍", "❤️", "👩🏽‍👩🏽‍👧🏽", "🇩🇪", "1️⃣", "❤️‍🔥"]) assert.ok(isOneEmoji(one), one);
  for (const not of ["", "a", "﷽", "👍 ", "👍👍", "‮👍", "x".repeat(40), 7]) assert.ok(!isOneEmoji(not), String(not));
});

test("a forwarded message's label is checked where it enters", () => {
  assert.deepEqual(forwarded({ name: "ann#0001", at: T }), { name: "ann#0001", at: T });
  assert.deepEqual(forwarded({ name: "‮  ", at: 0 }), { name: "someone", at: 0 });
  assert.equal(forwarded({ name: "ann", at: -1 }), undefined);
  assert.equal(forwarded({ name: "ann", at: 1.5 }), undefined);
  assert.equal(forwarded({ at: T }), undefined);
  assert.equal(forwarded({ name: "n".repeat(200), at: T })!.name.length, 64);
  assert.deepEqual(messageRefs({ fwd: { name: "ann", at: T } }), { fwd: { name: "ann", at: T } });
  // Through a hand-off and the archive, as it came
  const m = msg({ timestamp: T, id: "f", fwd: { name: "ann", at: T - 9 }, edited_at: T + 1 });
  assert.deepEqual(sanitizeHistory([m])[0].fwd, m.fwd);
  assert.equal(sanitizeHistory([m])[0].edited_at, T + 1);
  assert.deepEqual(fromArchived(toArchived(m)).fwd, m.fwd);
});

test("a message a stored copy replaces keeps what this reader saw done to it", () => {
  const shared = sanitizeHistory([msg({ timestamp: T, id: "s", ...ann })]);
  const reacted = applyEvent(shared, ev({ kind: "react", target: "s", emoji: "🔥", on: true }, ben, T + 1), { mayPin: false });
  const { messages } = mergeHistory(reacted, [msg({ timestamp: T, id: "s", user_id: 1, username: "ann#0001" })], "");
  assert.notEqual(messages[0].kind, "shared");
  assert.equal(reactionChips(messages[0], () => false)[0].emoji, "🔥");
  assert.equal(rowKey(messages[0]), rowKey(shared[0]), "and is the same row");
});

test("every emoji the pickers offer is one a reader takes as a reaction", () => {
  for (const e of [...QUICK_REACTIONS, ...EMOJI_CATEGORIES.flatMap((c) => c.emojis)]) assert.ok(isOneEmoji(e), e);
});

// ── 1.3.1 audit (Track B2a) ─────────────────────────────────────────────────

test("an id is cut by code points, as envelope.rs cuts it (R2-17)", () => {
  const astral = "😀".repeat(70);
  const [kept] = sanitizeHistory([{ user_id: 1, username: "a", content: "x", timestamp: T, id: astral, reply_to: astral }]);
  assert.equal(kept.id, "😀".repeat(64));
  assert.equal(kept.reply_to, "😀".repeat(64));
  assert.equal(messageRefs({ thread: "a".repeat(80) }).thread, "a".repeat(64));
});

test("a message's text is cut to 16 KiB where it arrives, at a character's edge (D-7)", () => {
  assert.equal(receivedText("hello"), "hello");
  const plain = "a".repeat(40_000);
  assert.equal(receivedText(plain).length, MAX_RECEIVED_BYTES);
  const euro = receivedText("€".repeat(9000));
  assert.equal(euro.length, Math.floor(MAX_RECEIVED_BYTES / 3));
  const emoji = receivedText("😀".repeat(9000));
  assert.equal(new TextEncoder().encode(emoji).length, MAX_RECEIVED_BYTES);
  assert.ok(!/[\ud800-\udbff]$/.test(emoji), "no half of a pair left at the end");
  const edge = "a".repeat(MAX_RECEIVED_BYTES - 1) + "😀";
  assert.equal(receivedText(edge), "a".repeat(MAX_RECEIVED_BYTES - 1), "a character that does not fit goes whole");
});

test("a notification never carries the text of a message with a timer (R2-14)", () => {
  const file = fileRef({ hash: "a".repeat(64), key: "b".repeat(64), size: 1, z: false, name: "cat.png" })!;
  assert.equal(notificationBody({ content: "**hi** ||secret||" }), "hi ▒▒▒");
  assert.equal(notificationBody({ content: "hi", expires_at: T }), "");
  assert.equal(notificationBody({ content: "", file }), "Sent a file: cat.png", "a file without a caption");
  assert.equal(notificationBody({ content: "", file, expires_at: T }), "");
  assert.equal(notificationBody({ content: "x".repeat(500) }).length, 140);
});

test("a field a later version kept in the archive survives this one's save (R2-03)", () => {
  const stored = {
    ...msg({ timestamp: T, id: "f" }),
    extra: JSON.stringify({ reply_to: "a", history: [{ at: 1, text: "old" }], reactions: "not a list" }),
  };
  const back = fromArchived(stored);
  assert.equal(back.reply_to, "a");
  assert.equal(back.reactions, undefined, "a known field that does not check is still dropped");
  assert.deepEqual(JSON.parse(back.extra_kept!), { history: [{ at: 1, text: "old" }] });
  // Saved again, after an edit made here: both there, ours over theirs
  const edited = applyEvent([back], ev({ kind: "edit", target: "f" }, { user_id: 1, username: "alice" }, T + 5, "new"), { mayPin: false })[0];
  const again = JSON.parse(toArchived(edited).extra!);
  assert.deepEqual(again, { history: [{ at: 1, text: "old" }], reply_to: "a", edited_at: T + 5 });
  assert.equal(fromArchived(toArchived(edited)).extra_kept, back.extra_kept, "and round again unchanged");
  // Never handed to anyone
  assert.equal(forHandOff(back).extra_kept, undefined);
  assert.equal(sanitizeHistory([back])[0].extra_kept, undefined);
  // A message with nothing unknown carries nothing
  assert.ok(!("extra_kept" in fromArchived(toArchived(msg({ timestamp: T, reply_to: "a" })))));
});

test("one long message cannot push the rest out of a hand-off (R2-07)", () => {
  const long = msg({ timestamp: T, id: "l", content: "x".repeat(40_000), reactions: [] });
  const offered = forHandOff(long);
  assert.equal(offered.content.length, 2000);
  assert.equal(offered.reactions, undefined);
  assert.equal(long.content.length, 40_000, "the message itself is untouched");
  const plain = msg({ timestamp: T, id: "p" });
  assert.equal(forHandOff(plain), plain, "a short plain one is offered as it is");
  const fifty = [long, ...Array.from({ length: 49 }, (_, i) => msg({ timestamp: T + i, id: `m${i}` }))].map(forHandOff);
  assert.ok(new TextEncoder().encode(JSON.stringify(fifty)).length < 48 * 1024);
});

test("a delete also takes hand-off copies that name its writer; an edit does not (D-13, R3-01)", () => {
  // Bob joined later: Ann's message reached him only as a member's copy
  const [shared] = sanitizeHistory([msg({ timestamp: T, id: "m1", ...ann, content: "my password is hunter2" })]);
  assert.equal(shared.account, undefined);
  const forger = { ...shared, username: "eve#0005" };
  const later = { ...shared, timestamp: T + 100 };
  const list = [shared, forger, later];
  const gone = applyEvent(list, ev({ kind: "delete", target: "m1" }, ann, T + 50), { mayPin: false });
  assert.equal(gone[0].kind, "deleted");
  assert.equal(gone[0].content, "");
  assert.equal(gone[1], forger, "a copy naming somebody else stays");
  assert.equal(gone[2], later, "a copy claiming a time after the delete stays");
  assert.equal(applyEvent(list, ev({ kind: "edit", target: "m1" }, ann, T + 50, "changed"), { mayPin: false }), list, "hearsay keeps what was handed on");
  // Negative: somebody else's delete takes nothing
  assert.equal(applyEvent(list, ev({ kind: "delete", target: "m1" }, ben, T + 50), { mayPin: false }), list);
});

test("a guest changes only what this connection received from them (R3-11)", () => {
  const list = conv();
  const notNow = { mayPin: false, current: () => false };
  // After a relay restart a newcomer has the old guest's id and types the old name
  assert.equal(applyEvent(list, ev({ kind: "edit", target: "m3" }, guest, T + 9, "x"), notNow), list);
  assert.equal(applyEvent(list, ev({ kind: "delete", target: "m3" }, guest, T + 9), notNow), list);
  // On the connection that received it: theirs
  const now = { mayPin: false, current: (m: ChatMessage) => m === list[2] };
  assert.equal(applyEvent(list, ev({ kind: "edit", target: "m3" }, guest, T + 9, "third!"), now)[2].content, "third!");
  // An account holder's message is theirs on any connection
  assert.equal(applyEvent(list, ev({ kind: "edit", target: "m1" }, ann, T + 9, "first!"), notNow)[0].content, "first!");
});

test("a full emoji lets go of those who took theirs off; look-alike emoji are refused (R3-12)", () => {
  let list = conv();
  const thumbs = (by: EventIn["by"], on: boolean, at: number) =>
    (list = applyEvent(list, ev({ kind: "react", target: "m2", emoji: "👍", on }, by, at), { mayPin: false }));
  for (let i = 0; i < MAX_REACTORS; i++) {
    const g = { user_id: 100 + i, username: `g${i}` };
    thumbs(g, true, T + i);
    thumbs(g, false, T + 100 + i);
  }
  thumbs(ann, true, T + 500);
  assert.deepEqual(reactionChips(list[1], (k) => k === "a:aa"), [{ emoji: "👍", count: 1, mine: true, names: ["ann#0001"] }]);
  for (const look of ["👍\u200c", "👍\ufe0e", "\u200c👍"]) assert.ok(!isOneEmoji(look), JSON.stringify(look));
  for (const one of ["❤️", "👩🏽‍👩🏽‍👧🏽", "🏴󠁧󠁢󠁳󠁣󠁴󠁿"]) assert.ok(isOneEmoji(one), one);
});

test("history cuts a long text, never inside an emote's token", () => {
  const tok = `<:pog:${"a".repeat(32)}>`;
  const text = `${"x".repeat(1990)}${tok} tail`;
  assert.equal(cutText(text), "x".repeat(1990));
  assert.ok(cutText(`${"x".repeat(1900)}${tok}${"y".repeat(200)}`).includes(tok), "a whole token stays");
  assert.equal(cutText("short <: not a token"), "short <: not a token");
});
