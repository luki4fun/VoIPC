// Where a swipe ends up. Pure arithmetic, so it is tested here rather than
// discovered on a phone — none of this reproduces in a desktop browser at
// 390px, because a mouse does not have a velocity worth reading.

import { test } from "node:test";
import assert from "node:assert/strict";
import { sampleVelocity, settle, type Pane } from "./swipe.ts";

const W = 390;

test("a short slow drag snaps back", () => {
  assert.equal(settle(1, 40, 0.05, W), 1);
  assert.equal(settle(1, -40, -0.05, W), 1);
});

test("dragging far enough changes pane", () => {
  // Dragging right reveals what is to the left: the channel drawer.
  assert.equal(settle(1, 150, 0.05, W), 0);
  assert.equal(settle(1, -150, -0.05, W), 2);
});

test("a flick counts even when it is short", () => {
  assert.equal(settle(1, 20, 0.9, W), 0);
  assert.equal(settle(1, -20, -0.9, W), 2);
});

test("the edges do not wrap around", () => {
  // Off the end of the track is the end of the track, not the other side.
  assert.equal(settle(0, 300, 1.2, W), 0);
  assert.equal(settle(2, -300, -1.2, W), 2);
});

test("a flick wins over the drag it contradicts", () => {
  // Dragged right, then flicked back left before letting go — which is what
  // changing your mind looks like. The later intention is the real one.
  assert.equal(settle(1, 150, -0.9, W), 2);
});

test("a wider viewport needs a longer drag", () => {
  // 150px is past a quarter of 390 but not of 800.
  assert.equal(settle(1, 150, 0.05, 390), 0);
  assert.equal(settle(1, 150, 0.05, 800), 1);
});

test("every outcome is a real pane", () => {
  for (const from of [0, 1, 2] as Pane[]) {
    for (const dx of [-400, -100, 0, 100, 400]) {
      for (const vx of [-2, 0, 2]) {
        const to = settle(from, dx, vx, W);
        assert.ok(to === 0 || to === 1 || to === 2, `${from} ${dx} ${vx} -> ${to}`);
      }
    }
  }
});

test("a flick reads as a flick", () => {
  // 20px a frame at 60Hz is a fast swipe. Note that nothing samples at release:
  // a flick ends with the finger already still, so the value read there is zero
  // and measuring only that is how a flick gets lost.
  let v = 0;
  for (let i = 0; i < 4; i++) v = sampleVelocity(v, -20, 16);
  assert.ok(v < -0.8, `${v}`);
  assert.equal(settle(1, -80, v, 390), 2);
});

test("slowing to a stop before lifting is not a flick", () => {
  // The deliberate version of changing your mind: drag, decelerate, let go.
  // Frames that report no movement are information, not noise — they are what
  // makes this different from the flick above, so they do count.
  let v = 0;
  for (let i = 0; i < 4; i++) v = sampleVelocity(v, -20, 16);
  for (const dx of [-8, -3, 0, 0]) v = sampleVelocity(v, dx, 16);
  assert.ok(Math.abs(v) < 0.4, `${v}`);
  // Short drag + no flick = stay put.
  assert.equal(settle(1, -80, v, 390), 1);
});

test("a slow drag never reads as a flick", () => {
  // 2px per frame is a deliberate, slow drag. It must stay well under the
  // 0.4px/ms the settle rule treats as a flick.
  let v = 0;
  for (let i = 0; i < 10; i++) v = sampleVelocity(v, -2, 16);
  assert.ok(Math.abs(v) < 0.4, `${v}`);
  assert.equal(settle(1, -60, v, 390), 1);
});

test("a zero-length frame changes nothing", () => {
  // Two pointer events with the same timestamp would otherwise divide by zero.
  assert.equal(sampleVelocity(-1.5, -10, 0), -1.5);
});
