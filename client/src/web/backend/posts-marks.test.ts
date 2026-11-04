import { test } from "node:test";
import assert from "node:assert/strict";
import { postsMarks } from "./posts-marks.ts";

const shape = { account: null, name: "gus#0001", since_ms: 1000, before_ms: 2000, by: "bobby" };

test("what the browser's decoder gives comes out as plain numbers and null", () => {
  const [m] = postsMarks([{ name: "gus#0001", since_ms: 1000n, before_ms: 2000n, by: "bobby" }]);
  assert.deepEqual(m, shape);
  assert.equal(typeof m.since_ms, "number");
  assert.equal(m.account, null, "not undefined");
});

test("an account stays as it came, the bytes", () => {
  const account = new Array(16).fill(7);
  assert.deepEqual(postsMarks([{ ...shape, account, since_ms: 1000n, before_ms: 2000n }])[0], { ...shape, account });
});

test("what the desktop's event holds already goes through unchanged, so both agree", () => {
  assert.deepEqual(postsMarks([shape]), [shape]);
  assert.deepEqual(JSON.parse(JSON.stringify(postsMarks([shape]))), [shape]);
  assert.deepEqual(postsMarks([]), []);
});
