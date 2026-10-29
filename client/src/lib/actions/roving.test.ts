// Where an arrow key goes in a tab list or a radio group. The DOM half (one
// Tab stop, the pick by click) is checked in a browser.

import { test } from "node:test";
import assert from "node:assert/strict";
import { step } from "./roving.ts";

test("the arrows move along the items and wrap at the ends", () => {
  assert.equal(step(0, 3, "ArrowRight"), 1);
  assert.equal(step(2, 3, "ArrowRight"), 0);
  assert.equal(step(2, 3, "ArrowDown"), 0);
  assert.equal(step(0, 3, "ArrowLeft"), 2);
  assert.equal(step(1, 3, "ArrowUp"), 0);
  assert.equal(step(1, 3, "Home"), 0);
  assert.equal(step(0, 3, "End"), 2);
});

test("other keys, and an empty group, are left alone", () => {
  assert.equal(step(0, 3, "Tab"), null);
  assert.equal(step(0, 3, "Enter"), null);
  assert.equal(step(0, 3, " "), null);
  assert.equal(step(0, 0, "ArrowRight"), null);
});
