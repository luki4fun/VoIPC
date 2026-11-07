// A list from a relay can repeat an id, and a keyed each throws on a repeat.

import { test } from "node:test";
import assert from "node:assert/strict";

import { eachOnce } from "./upsert.ts";

test("a repeat keeps its first place and its last row", () => {
  const numbers = eachOnce(
    [
      { id: 2, v: "a" },
      { id: 1, v: "x" },
      { id: 2, v: "b" },
    ],
    (r) => r.id,
  );
  assert.deepEqual(numbers.map((r) => r.id), [2, 1]);
  assert.equal(numbers[0].v, "b");

  const strings = eachOnce(
    [
      { id: "two", v: "a" },
      { id: "one", v: "x" },
      { id: "two", v: "b" },
    ],
    (r) => r.id,
  );
  assert.deepEqual(strings.map((r) => r.id), ["two", "one"]);
  assert.equal(strings[0].v, "b");
});

test("distinct rows all stay, in order", () => {
  const rows = [{ id: 3 }, { id: 1 }, { id: 2 }];
  assert.deepEqual(eachOnce(rows, (r) => r.id), rows);
});
