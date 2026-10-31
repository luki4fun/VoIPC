import { test } from "node:test";
import assert from "node:assert/strict";
import { FIT, MAX_SCALE, clampView, containRect, panBy, toggleAt, zoomAt } from "./zoom-rules.ts";

const W = 400;
const H = 300;

test("zooming keeps the point under the fingers where it was", () => {
  const v = zoomAt(FIT, 2, 100, 50, W, H);
  assert.equal(v.scale, 2);
  // The box point (100, 50) showed stage point (100, 50); after zooming it
  // must still show it: x + 100 * 2 === 100
  assert.equal(v.x + 100 * v.scale, 100);
  assert.equal(v.y + 50 * v.scale, 50);
});

test("the picture never zooms out past fitting, nor in past the cap", () => {
  assert.equal(zoomAt(FIT, 0.5, 10, 10, W, H).scale, 1);
  assert.equal(zoomAt(FIT, 100, 10, 10, W, H).scale, MAX_SCALE);
});

test("panning stops at the edges: the box is never left half empty", () => {
  const zoomed = zoomAt(FIT, 2, 0, 0, W, H);
  assert.deepEqual(panBy(zoomed, 500, 500, W, H), { scale: 2, x: 0, y: 0 });
  assert.deepEqual(panBy(zoomed, -5000, -5000, W, H), { scale: 2, x: W - W * 2, y: H - H * 2 });
  // Fitted, there is nothing to pan
  assert.deepEqual(panBy(FIT, 40, 40, W, H), FIT);
});

test("a double tap zooms in where it landed, and a second one fits again", () => {
  const inView = toggleAt(FIT, 200, 150, W, H);
  assert.ok(inView.scale > 2);
  assert.deepEqual(toggleAt(inView, 10, 10, W, H), FIT);
});

test("a view from a bigger box is pulled back inside a smaller one", () => {
  const v = clampView({ scale: 2, x: -700, y: 0 }, W, H);
  assert.equal(v.x, W - W * 2);
});

test("a fitted picture pans only as far as its own edges", () => {
  // A wide picture in the 400×300 box: drawn 400×200, with 50 px bands above and below
  const c = containRect(800, 400, W, H);
  assert.deepEqual(c, { x: 0, y: 50, w: 400, h: 200 });
  // At 1.25 it is 250 high, still inside the box: centred, no pan up or down
  const low = zoomAt(FIT, 1.25, W / 2, H / 2, W, H, c);
  assert.equal(panBy(low, 0, 500, W, H, c).y, panBy(low, 0, -500, W, H, c).y);
  // At 2 it is 400 high: its top meets the box's top, its bottom the bottom
  const v = zoomAt(FIT, 2, W / 2, H / 2, W, H, c);
  assert.equal(panBy(v, 0, 5000, W, H, c).y, -100);
  assert.equal(panBy(v, 0, -5000, W, H, c).y, H - 2 * 250);
  // Without a picture's rect, the whole stage as before
  assert.equal(panBy(v, 0, 5000, W, H).y, 0);
});
