import { test } from "node:test";
import assert from "node:assert/strict";
import { place } from "./place-rules.ts";

// A 360x640 phone, 8 px in from each edge, with a 24 px status bar on top
const PHONE = { left: 8, top: 32, right: 352, bottom: 632 };

test("a pop-up that fits opens where it was asked for", () => {
  assert.deepEqual(place({ x: 40, y: 100, w: 240, h: 120, up: 90 }, PHONE), { x: 40, y: 100 });
});

test("near the right edge it moves in, not off the screen", () => {
  assert.deepEqual(place({ x: 300, y: 100, w: 240, h: 120, up: 90 }, PHONE), { x: 112, y: 100 });
});

test("with no room below it goes above what opened it, by its measured height", () => {
  // An emote card with an error line is taller than the 140 px once guessed
  assert.deepEqual(place({ x: 40, y: 560, w: 240, h: 180, up: 548 }, PHONE), { x: 40, y: 368 });
});

test("with room neither below nor above, it stays on screen and covers the opener", () => {
  // The keyboard is up: little is visible, and the picker is tall
  const short = { left: 8, top: 32, right: 352, bottom: 330 };
  assert.deepEqual(place({ x: 40, y: 200, w: 300, h: 260, up: 190 }, short), { x: 40, y: 70 });
});

test("a pop-up taller than the screen starts at its top edge", () => {
  assert.deepEqual(place({ x: 40, y: 300, w: 240, h: 900, up: 290 }, PHONE), { x: 40, y: 32 });
});

test("a pop-up asked for above the top edge comes down onto the screen", () => {
  assert.deepEqual(place({ x: 40, y: 10, w: 240, h: 100, up: 0 }, PHONE), { x: 40, y: 32 });
});
