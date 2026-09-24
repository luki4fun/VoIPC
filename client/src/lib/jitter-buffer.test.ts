// The browser listener's jitter buffer, which lives in the mixer worklet. It is
// a port of crates/voipc-audio/src/jitter.rs and these are ports of its tests,
// so `cargo test -p voipc-audio` and `npm test` hold the two to the same rules.
//
// `currentTime` stays 0 under Node, so every timed window reads as "just now";
// a buffer whose lastChange is still null is what lets a decay through.

import { test } from "node:test";
import assert from "node:assert/strict";
import { JitterBuffer, LOST, SHED_AFTER } from "../web/backend/worklets/mixer-worklet.js";

const pcm = (v: number) => new Float32Array([v]);

test("a short stall is bridged with silence and the late frame still plays", () => {
  const jb = new JitterBuffer(2);
  jb.push(0, pcm(0));
  jb.push(1, pcm(1));
  assert.deepEqual(jb.pop(), pcm(0));
  assert.deepEqual(jb.pop(), pcm(1));

  // Nothing there yet: concealed, and still expecting seq 2
  assert.equal(jb.pop(), LOST);
  assert.equal(jb.pop(), LOST);

  const late = pcm(2);
  jb.push(2, late);
  assert.equal(jb.pop(), late, "the late frame was given up on");
  assert.equal(jb.targetDelay, 3, "a bridged stall must deepen the cushion");

  // A speaker who stopped: conceal the tail, then go quiet
  for (let i = 0; i < 3; i++) assert.equal(jb.pop(), LOST);
  assert.equal(jb.pop(), null);
});

test("only a phrase with a frame to spare decays", () => {
  const jb = new JitterBuffer(3);
  for (let s = 0; s < 3; s++) jb.push(s, pcm(s));
  for (let s = 0; s < 3; s++) assert.deepEqual(jb.pop(), pcm(s));
  // Arrives into an empty buffer: this phrase ran dry
  jb.push(3, pcm(3));
  assert.deepEqual(jb.pop(), pcm(3));
  jb.reset();
  assert.equal(jb.targetDelay, 3, "a phrase that ran dry decayed");

  for (let s = 10; s < 13; s++) jb.push(s, pcm(s));
  assert.deepEqual(jb.pop(), pcm(10));
  jb.push(13, pcm(13)); // two still waiting
  while (jb.pop() instanceof Float32Array);
  jb.reset();
  assert.equal(jb.targetDelay, 2, "a phrase with a frame to spare did not decay");
});

test("a standing surplus is reported once a second", () => {
  const jb = new JitterBuffer(2);
  for (let s = 0; s < 7; s++) jb.push(s, pcm(s));
  for (let i = 0; i < SHED_AFTER; i++) {
    assert.equal(jb.takeSurplus(), false, `shed early, after ${i} pops`);
    jb.pop();
    jb.push(7 + i, pcm(7 + i));
  }
  assert.equal(jb.takeSurplus(), true);
  assert.equal(jb.takeSurplus(), false, "one shed per second, not one per frame");
});
