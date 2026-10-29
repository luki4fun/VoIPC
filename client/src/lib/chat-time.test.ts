import { test } from "node:test";
import assert from "node:assert/strict";
import { dayKey, dayLabel } from "./chat-time.ts";

const NOON = new Date(2026, 9, 26, 12, 0, 0).getTime();
const HOUR = 3_600_000;

test("the same calendar day is one day, midnight is a new one", () => {
  assert.equal(dayKey(NOON), dayKey(NOON + 6 * HOUR));
  assert.notEqual(dayKey(NOON), dayKey(NOON + 13 * HOUR));
});

test("today and yesterday are said in words", () => {
  assert.equal(dayLabel(NOON - HOUR, NOON, "en-GB"), "Today");
  assert.equal(dayLabel(NOON - 24 * HOUR, NOON, "en-GB"), "Yesterday");
});

test("older days get their date, and a year only when it is another one", () => {
  const lastWeek = dayLabel(NOON - 5 * 24 * HOUR, NOON, "en-GB");
  assert.ok(!/2026/.test(lastWeek), lastWeek);
  const lastYear = dayLabel(new Date(2025, 0, 3, 10).getTime(), NOON, "en-GB");
  assert.ok(/2025/.test(lastYear), lastYear);
});
