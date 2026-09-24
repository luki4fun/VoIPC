// The browser sharer's pacing and keyframe rules. Pure functions only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { KEYFRAME_INTERVAL_MS, paceFrame, shouldForceKey } from "./share-rules.ts";

/** One frame at 60 fps, in µs. */
const I = 16667;

test("frames are paced on the capture clock", () => {
  assert.equal(paceFrame(-Infinity, 5000, I), 5000, "the first frame is always on time");
  // A little early is on time, and the deadline steps from the last one
  assert.equal(paceFrame(100000, 96000, I), 116667);
  assert.equal(paceFrame(100000, 90000, I), null, "too early: held back");
  // Late: the deadline restarts from the frame, not a run of catch-up frames
  assert.equal(paceFrame(100000, 150000, I), 150000);
  assert.equal(paceFrame(5000000, 1000, I), 1000, "a clock that went back is a new clock");
});

test("a backed-up uplink gets one keyframe a second, not one a frame", () => {
  assert.equal(shouldForceKey(false, 1000, 5000, 0), false, "nothing asked, nothing due");
  assert.equal(shouldForceKey(true, 1000, 200, 0), true, "asked, uplink clear");
  assert.equal(shouldForceKey(true, 1000, 200, 12), false, "the storm");
  assert.equal(shouldForceKey(true, 1000, 1000, 12), true, "spaced out, still sent");
  assert.equal(shouldForceKey(false, KEYFRAME_INTERVAL_MS, 5000, 3), true, "the periodic IDR");
});
