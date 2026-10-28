import { test } from "node:test";
import assert from "node:assert/strict";
import { ambiguousTarget, findTarget, isOwn, threadView } from "./thread-rules.ts";
import type { ChatMessage } from "./types.ts";

const T = 1_700_000_000_000;
let clock = 0;
function m(id: string, user: string, over: Partial<ChatMessage> = {}): ChatMessage {
  return { id, user_id: user.charCodeAt(0), username: user, content: id, timestamp: T + ++clock, ...over };
}

test("a reply finds what it answers: first-hand first, then the earliest", () => {
  const original = m("a", "ann");
  const copy = m("a", "ann", { kind: "shared", timestamp: T - 50 });
  const again = m("a", "ann");
  assert.equal(findTarget([again, copy, original], "a"), original);
  assert.equal(findTarget([copy], "a"), copy, "a shared copy when that is all there is");
  assert.equal(findTarget([original], "zz"), undefined);
  assert.equal(findTarget([original], undefined), undefined);
  assert.equal(findTarget([m("n", "x", { kind: "notice" })], "n"), undefined, "our own lines are never answered");
});

test("a copy written after the reply never takes over its quote (R2-09)", () => {
  // Dave holds Alice's message and Carol's answer only as shared copies; then
  // Mallory sends a live message under Alice's id
  const alice = m("x", "alice", { kind: "shared" });
  const carol = m("c", "carol", { kind: "shared", reply_to: "x" });
  const mallory = m("x", "mallory", { timestamp: carol.timestamp + 10 * 60_000 });
  const list = [alice, carol, mallory];
  assert.equal(findTarget(list, "x", carol.timestamp), alice);
  assert.equal(ambiguousTarget(list, "x", carol.timestamp), false);
  // Within the clocks' slack it is not later: two writers, so no answer, said so
  const close = m("x", "mallory", { timestamp: carol.timestamp + 30_000 });
  assert.equal(findTarget([alice, carol, close], "x", carol.timestamp), undefined);
  assert.equal(ambiguousTarget([alice, carol, close], "x", carol.timestamp), true);
  // A thread folds under the first message, never under a later one
  const t = m("t", "carol", { kind: "shared", thread: "x", reply_to: "x" });
  const view = threadView([alice, t, m("x", "mallory", { timestamp: t.timestamp + 600_000 })], { auto: false });
  assert.deepEqual(view.threads.get(alice), [t]);
});

test("two writers' messages under one id leave a reply unanswered (S-009)", () => {
  const real = m("a", "ann");
  // A forged copy that claims an earlier time, from the stored log or a hand-off
  const forged = m("a", "eve", { timestamp: real.timestamp - 60_000 });
  const reply = m("r", "bob", { reply_to: "a" });
  assert.equal(findTarget([forged, real, reply], "a", reply.timestamp), undefined);
  assert.equal(ambiguousTarget([forged, real, reply], "a", reply.timestamp), true);
  // A thread on such an id does not fold
  const t = m("t", "bob", { thread: "a", reply_to: "a" });
  const view = threadView([forged, real, t], { auto: false });
  assert.equal(view.threads.size, 0);
  assert.ok(view.orphans.has(t));
  assert.equal(ambiguousTarget([real, reply], "a", reply.timestamp), false);
});

test("mine: the account where both have one, else this connection's id on what it received (R2-10)", () => {
  const now = new Set<ChatMessage>();
  const current = (x: ChatMessage) => now.has(x);
  const archived = m("o", "ann", { user_id: 5 });
  const live = m("l", "me", { user_id: 5 });
  now.add(live);
  const me = { user_id: 5 };
  assert.equal(isOwn(live, me, current), true);
  assert.equal(isOwn(archived, me, current), false, "an old message under a reused id is not ours");
  assert.equal(isOwn({ ...live, kind: "shared" }, me, () => true), false, "a handed-over copy never is");
  const signed = { user_id: 5, account: "aa" };
  assert.equal(isOwn(m("k", "me", { user_id: 77, account: "aa" }), signed, current), true, "our account, any connection");
  assert.equal(isOwn(m("k", "x", { user_id: 5, account: "bb" }), signed, () => true), false, "someone else's account");
  assert.equal(isOwn(live, signed, current), true, "a guest's message of this connection under our id");
  assert.equal(isOwn(m("z", "x", { user_id: 0 }), { user_id: 0 }, () => true), false, "nobody is id 0");
});

test("answers sent into a thread leave the main flow", () => {
  const root = m("r", "ann");
  const t1 = m("t1", "bob", { reply_to: "r", thread: "r" });
  const t2 = m("t2", "ann", { reply_to: "t1", thread: "r" });
  const later = m("x", "cat");
  const view = threadView([root, t1, t2, later], { auto: false });
  assert.deepEqual(view.main, [root, later]);
  assert.deepEqual(view.threads.get(root), [t1, t2]);
});

test("a busy message becomes a thread on its own, and only with grouping on", () => {
  const root = m("r", "ann");
  const r1 = m("1", "bob", { reply_to: "r" });
  const r2 = m("2", "cat", { reply_to: "1" });
  const between = m("b", "dan");
  const r3 = m("3", "bob", { reply_to: "r" });
  const list = [root, r1, r2, between, r3];
  const on = threadView(list, { auto: true });
  assert.deepEqual(on.main, [root, between]);
  assert.deepEqual(on.threads.get(root), [r1, r2, r3], "answers to answers count");
  const off = threadView(list, { auto: false });
  assert.deepEqual(off.main, list);
  assert.equal(off.threads.size, 0);
  // One person answering themselves three times is not a conversation
  const solo = [root, m("s1", "bob", { reply_to: "r" }), m("s2", "bob", { reply_to: "r" }), m("s3", "bob", { reply_to: "r" })];
  assert.equal(threadView(solo, { auto: true }).threads.size, 0);
});

test("an answer in a thread whose first message is gone stays in sight", () => {
  const lost = m("t", "bob", { reply_to: "gone", thread: "gone" });
  const view = threadView([m("a", "ann"), lost], { auto: true });
  assert.ok(view.main.includes(lost));
  assert.ok(view.orphans.has(lost));
});

test("a thread's first message keeps its thread even when it answers something", () => {
  const x = m("x", "ann");
  const root = m("r", "bob", { reply_to: "x" });
  const t1 = m("t1", "cat", { thread: "r", reply_to: "r" });
  const view = threadView([x, root, t1, m("y", "dan", { reply_to: "x" }), m("z", "eve", { reply_to: "x" })], { auto: true });
  assert.deepEqual(view.threads.get(root), [t1]);
  assert.ok(view.main.includes(root), "it is not folded into the thread above it");
});

test("a forged loop of answers ends", () => {
  const a = m("a", "ann", { reply_to: "b" });
  const b = m("b", "bob", { reply_to: "a" });
  const view = threadView([a, b], { auto: true });
  assert.equal(view.main.length, 2);
});
