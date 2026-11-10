import { test } from "node:test";
import assert from "node:assert/strict";
import { afterMark, rowMark } from "./marks-rules.ts";

test("the first sight of a channel is the baseline: no ring for a new member", () => {
  assert.deepEqual(afterMark(undefined, 5000), { read: 5000, ring: false });
});

test("zero is a relay that restarted: never a false ring", () => {
  assert.deepEqual(afterMark(5000, 0), { read: 5000, ring: false });
  assert.deepEqual(afterMark(undefined, 0), { read: undefined, ring: false });
});

test("someone wrote after where they read: a ring, and the position stays", () => {
  assert.deepEqual(afterMark(5000, 60_000), { read: 5000, ring: true });
});

test("nothing new: no ring, and our own post by our own clock does not light one", () => {
  assert.deepEqual(afterMark(60_000, 60_000), { read: 60_000, ring: false });
  assert.deepEqual(afterMark(60_000, 64_000), { read: 60_000, ring: false }, "the two clocks apart");
});

test("a row shows a count over a dot over a ring", () => {
  const row = { left: false, level: "mentions" as const, unread: 0, unseen: false, ring: false };
  assert.equal(rowMark(row), null);
  assert.equal(rowMark({ ...row, ring: true }), "ring");
  assert.equal(rowMark({ ...row, ring: true, unseen: true }), "dot");
  assert.equal(rowMark({ ...row, ring: true, unseen: true, unread: 2 }), "count");
});

test("a channel left, or set to nothing, stays plain", () => {
  const lit = { unread: 2, unseen: true, ring: true };
  assert.equal(rowMark({ left: true, level: "all", ...lit }), null);
  assert.equal(rowMark({ left: false, level: "nothing", ...lit }), null);
});
