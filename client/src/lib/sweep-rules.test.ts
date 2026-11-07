import { test } from "node:test";
import assert from "node:assert/strict";
import { firstSweepDelay, mayMoveUp, nextSweepDelay, pageBytes, pagePeople, SWEEP_EVERY_MS } from "./sweep-rules.ts";
import type { UserInfo } from "./types.ts";

test("the first sweep falls somewhere in the first minute", () => {
  assert.equal(firstSweepDelay(0), 0);
  assert.ok(firstSweepDelay(0.999) < 60_000);
});

test("ten minutes between sweeps, more when a sweep is large", () => {
  assert.equal(nextSweepDelay(0), SWEEP_EVERY_MS);
  assert.equal(nextSweepDelay(24_000), SWEEP_EVERY_MS, "exactly the budget");
  assert.equal(nextSweepDelay(600_000), 15_000_000, "600 KB takes more than four hours");
});

test("a stranger's ask moves a sweep up only within the budget", () => {
  assert.equal(mayMoveUp(1000, 0), true, "nothing asked yet");
  assert.equal(mayMoveUp(1000, 4000), false);
  assert.equal(mayMoveUp(100_000, 4000), true);
});

test("a page costs by what it holds", () => {
  assert.equal(pageBytes(2000, 0), 6000);
  assert.equal(pageBytes(0, 10), 830);
});

test("a bare id is someone a list here names, and one nobody names is left out", () => {
  const row = (user_id: number) => ({ user_id, username: `u${user_id}` }) as UserInfo;
  const people = pagePeople([1, 2], [row(3)], (id) => (id === 1 ? row(1) : undefined));
  assert.deepEqual(people.map((u) => u.user_id).sort(), [1, 3]);
});
