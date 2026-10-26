import { test } from "node:test";
import assert from "node:assert/strict";
import { findTarget, threadView } from "./thread-rules.ts";
import type { ChatMessage } from "./types.ts";

const T = 1_700_000_000_000;
let clock = 0;
function m(id: string, user: string, over: Partial<ChatMessage> = {}): ChatMessage {
  return { id, user_id: user.charCodeAt(0), username: user, content: id, timestamp: T + ++clock, ...over };
}

test("a reply finds what it answers: first-hand first, then the earliest", () => {
  const original = m("a", "ann");
  const copy = m("a", "eve", { kind: "shared", timestamp: T - 50 });
  const impostor = m("a", "eve");
  assert.equal(findTarget([impostor, copy, original].reverse(), "a"), original);
  assert.equal(findTarget([original, impostor], "a"), original, "the later one is the copy");
  assert.equal(findTarget([original], "zz"), undefined);
  assert.equal(findTarget([original], undefined), undefined);
  assert.equal(findTarget([m("n", "x", { kind: "notice" })], "n"), undefined, "our own lines are never answered");
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
