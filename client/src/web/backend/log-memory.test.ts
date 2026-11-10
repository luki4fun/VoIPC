import { test } from "node:test";
import assert from "node:assert/strict";
import { freshPage, keepMemory, markReplay, wholeMemory } from "./log-memory.ts";

const stored = JSON.stringify({ cursors: { "d:a": 5, "c:b": 9 }, readers: { "c:b": [[1]] }, vault_gens: { "item.pins": 3 } });

test("a fresh page reads everything back, and keeps all the rest of the memory", () => {
  const { json, seen } = freshPage(stored);
  assert.deepEqual(JSON.parse(json!), { cursors: {}, vault_gens: { "item.pins": 3 } });
  assert.deepEqual(seen, { "d:a": 5, "c:b": 9 });
});

test("who was named lives apart, and a memory from before that hands it over", () => {
  const from = JSON.stringify({ readers: { "c:b": [[2]] }, named: {} });
  assert.deepEqual(JSON.parse(freshPage(stored).named!), { readers: { "c:b": [[1]] }, named: {} });
  assert.deepEqual(JSON.parse(freshPage(stored, from).named!), { readers: { "c:b": [[2]] }, named: {} });
  assert.equal(freshPage(JSON.stringify({ cursors: {} })).named, null);
  assert.deepEqual(JSON.parse(wholeMemory(freshPage(stored, from))!), {
    cursors: {},
    vault_gens: { "item.pins": 3 },
    readers: { "c:b": [[2]] },
    named: {},
  });
  assert.equal(wholeMemory(freshPage(null)), null);
  assert.deepEqual(JSON.parse(wholeMemory(freshPage(null, from))!).readers, { "c:b": [[2]] });
});

test("a first visit, or a memory that does not parse, starts empty", () => {
  assert.deepEqual(freshPage(null), { json: null, named: null, seen: {} });
  assert.deepEqual(freshPage("{nope"), { json: null, named: null, seen: {} });
  assert.deepEqual(freshPage("7"), { json: null, named: null, seen: {} });
});

test("a reload partway through a read loses nothing of what was read before", () => {
  const { seen } = freshPage(stored);
  // The session has only got through part of one conversation, and a new one
  const kept = JSON.parse(keepMemory(JSON.stringify({ cursors: { "d:a": 2, "d:n": 4 }, readers: {} }), seen));
  assert.deepEqual(kept.cursors, { "d:a": 5, "c:b": 9, "d:n": 4 });
  assert.deepEqual(kept.readers, {});
  // And further than the last page got counts too
  assert.equal(JSON.parse(keepMemory(JSON.stringify({ cursors: { "d:a": 8 } }), seen)).cursors["d:a"], 8);
});

test("what an earlier page read is a replay, what it did not is news", () => {
  const { seen } = freshPage(stored);
  const dm = (seq: number) => ({ conv: "d:a", seq, content: "hi" });
  assert.equal((markReplay("stored-dm", dm(5), seen) as { replay?: boolean }).replay, true);
  assert.equal((markReplay("stored-dm", dm(6), seen) as { replay?: boolean }).replay, undefined);
  assert.equal(
    (markReplay("stored-channel-message", { conv: "c:b", seq: 1 }, seen) as { replay?: boolean }).replay,
    true,
  );
  assert.equal(
    (markReplay("stored-dm", { conv: "d:other", seq: 1 }, seen) as { replay?: boolean }).replay,
    undefined,
  );
  // Other events pass as they are, even a payload that looks like one
  const other = { conv: "d:a", seq: 1 };
  assert.equal(markReplay("dm-kept", other, seen), other);
});
