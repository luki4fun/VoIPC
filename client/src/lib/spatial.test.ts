// Node's built-in runner, no framework: `npm test` in client/.
//
// The same table is asserted in crates/voipc-audio/src/spatial.rs, so the
// desktop mixer and the browser worklet cannot drift apart unnoticed:
// `cargo test -p voipc-audio` and `npm test` fail together.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BLOOM,
  DEFAULT_RANGE,
  MAX_MUFFLE,
  REF_DIST,
  TEST_HEIGHT,
  TEST_HEIGHT_SECS,
  TEST_ORBIT_SECS,
  TEST_RADIUS,
  TEST_VOICE_HZ,
  WIDTH,
  checkGoldenValues,
  defaultListener,
  defaultSource,
  gains,
  testLabel,
  testSource,
  testVoiceFrame,
  testVoiceSample,
} from "./spatial.ts";

test("the golden table matches the Rust mixer", () => {
  assert.equal(checkGoldenValues(), null);
});

test("constants are the ones spatial.rs pins", () => {
  assert.deepEqual([REF_DIST, WIDTH, BLOOM, DEFAULT_RANGE, MAX_MUFFLE], [1.5, 0.85, 0.5, 20, 10]);
  assert.deepEqual(
    [TEST_RADIUS, TEST_ORBIT_SECS, TEST_HEIGHT, TEST_HEIGHT_SECS, TEST_VOICE_HZ],
    [3, 8, 4, 16, 180],
  );
});

test("test voice samples match the Rust generator", () => {
  assert.ok(Math.abs(testVoiceSample(6017) - -0.0577201) < 1e-5);
  assert.ok(Math.abs(testVoiceSample(18_500) - 0.0877542) < 1e-5);
  assert.equal(testVoiceSample(40_000), 0);
  const frame = testVoiceFrame(960);
  assert.equal(frame.length, 960);
  assert.equal(frame[5], Math.fround(testVoiceSample(965)));
});

test("the label names the quarter and the height", () => {
  assert.equal(testLabel("2d", 0), "in front of you, 3.0 m away");
  assert.equal(testLabel("2d", 2), "on your right, 3.0 m away");
  assert.equal(testLabel("2d", 4), "behind you, 3.0 m away");
  assert.equal(testLabel("2d", 6), "on your left, 3.0 m away");
  assert.equal(testLabel("3d", 0), "in front of you, 3.0 m away, at ear level");
  assert.equal(testLabel("3d", 4), "behind you, 5.0 m away, 4.0 m above you");
  assert.equal(testLabel("3d", 12), "behind you, 5.0 m away, 4.0 m below you");
});

test("an unplaced or non-proximity source is untouched", () => {
  const lis = defaultListener();
  assert.deepEqual(gains("2d", lis, null), { l: 1, r: 1, lpA: 1 });
  assert.deepEqual(gains("off", lis, defaultSource([9, 9, 9])), { l: 1, r: 1, lpA: 1 });
});

test("the 3d test is quieter at the top of its sweep than at ear level", () => {
  const lis = defaultListener();
  const power = (t: number) => {
    const g = gains("3d", lis, testSource("3d", t));
    return Math.hypot(g.l, g.r);
  };
  assert.ok(power(4) < power(0), `${power(4)} should be below ${power(0)}`);
});
